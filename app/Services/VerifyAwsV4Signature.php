<?php

namespace App\Services;

use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Http\Request;
use Psr\Http\Message\RequestInterface;

class VerifyAwsV4Signature
{
    const ISO8601_BASIC = 'Ymd\THis\Z';

    public function __invoke(Request $request)
    {
        $authHeader = $request->header('authorization');
        if (substr($authHeader, 0, 16) !== 'AWS4-HMAC-SHA256') {
            \Illuminate\Support\Facades\Log::error('INVALID AUTHORIZATION HEADER: ' . $authHeader);
            return;
        }
        // AWS4-HMAC-SHA256 Credential=MY_AWS_ACCESS_KEY_ID/20240502/LOCAL-REGION/s3/aws4_request,
        // SignedHeaders=host;x-amz-acl;x-amz-content-sha256;x-amz-date;x-amz-user-agent,
        // Signature=15472357465f9a5b817079839fb646c68455f0f2a94bd808e78926a6ca36c591
        $authHeader = trim(substr($authHeader, 16));
        foreach (explode(',', $authHeader) as $dataItem) {
            $data = explode('=', trim($dataItem));
            if ($data[0] === 'Credential') {
                $credentials = $data[1] ?? '';
            } elseif ($data[0] === 'SignedHeaders') {
                $signedHeaders = explode(';', $data[1] ?? '');
            } elseif ($data[0] === 'Signature') {
                $signature = $data[1] ?? '';
            }
        }

        $secretKey = 'MY_AWS_ACCESS_KEY';

        $credParts = explode('/', $credentials);
        // todo validate region
        $region = $credParts[2] ?? '';
        $service = $credParts[3] ?? '';

        $ldt = gmdate(self::ISO8601_BASIC);
        $sdt = substr($ldt, 0, 8);
        $cs = explode('/', $credentials ?? '', 2)[1] ?? '';
        $parsedRequest = $this->parseRequest($request);
        $payload = hash('sha256', $request->getContent());

        $context = $this->createContext($parsedRequest, $payload, $signedHeaders);
        $toSign = $this->createStringToSign($ldt, $cs, $context['creq']);
        $signingKey = $this->getSigningKey(
            $sdt,
            $region,
            $service,
            $secretKey
        );
        return hash_hmac('sha256', $toSign, $signingKey) !== $signature;
    }

    private function parseRequest(Request $request)
    {
        // Clean up any previously set headers.
        /** @var RequestInterface $request */
        $uri = $request->getUri();

        return [
            'method'  => $request->getMethod(),
            'path'    => $request->path(),
            'query'   => $request->query->all(),
            'uri'     => $uri,
            'headers' => $request->header(),
            'body'    => $request->getContent(),
            'version' => $request->getProtocolVersion()
        ];
    }

    private function createContext(array $parsedRequest, string $payload, array $signedHeaders)
    {
        // Normalize the path as required by SigV4
        $canon = $parsedRequest['method'] . "\n"
            . $this->createCanonicalizedPath($parsedRequest['path']) . "\n"
            . $this->getCanonicalizedQuery($parsedRequest['query']) . "\n";

        // Case-insensitively aggregate all of the headers.
        $aggregate = [];
        foreach ($parsedRequest['headers'] as $key => $values) {
            $key = strtolower($key);
            if (isset($signedHeaders[$key])) {
                foreach ($values as $v) {
                    $aggregate[$key][] = $v;
                }
            }
        }

        ksort($aggregate);
        $canonHeaders = [];
        foreach ($aggregate as $k => $v) {
            if (count($v) > 0) {
                sort($v);
            }
            $canonHeaders[] = $k . ':' . preg_replace('/\s+/', ' ', implode(',', $v));
        }

        $signedHeadersString = implode(';', array_keys($aggregate));
        $canon .= implode("\n", $canonHeaders) . "\n\n"
            . $signedHeadersString . "\n"
            . $payload;

        return ['creq' => $canon, 'headers' => $signedHeadersString];
    }

    protected function createCanonicalizedPath(string $path): string
    {
        $doubleEncoded = rawurlencode(ltrim($path, '/'));

        return '/' . str_replace('%2F', '/', $doubleEncoded);
    }

    private function getCanonicalizedQuery(array $query): string
    {
        unset($query['X-Amz-Signature']);

        if (!$query) {
            return '';
        }

        $qs = '';
        ksort($query);
        foreach ($query as $k => $v) {
            if (!is_array($v)) {
                $qs .= rawurlencode($k) . '=' . rawurlencode($v !== null ? $v : '') . '&';
            } else {
                sort($v);
                foreach ($v as $value) {
                    $qs .= rawurlencode($k) . '=' . rawurlencode($value !== null ? $value : '') . '&';
                }
            }
        }

        return substr($qs, 0, -1);
    }

    private function createStringToSign($longDate, $credentialScope, $creq)
    {
        $hash = hash('sha256', $creq);

        return "AWS4-HMAC-SHA256\n{$longDate}\n{$credentialScope}\n{$hash}";
    }

    private function getSigningKey($shortDate, $region, $service, $secretKey)
    {
        $dateKey = hash_hmac(
            'sha256',
            $shortDate,
            "AWS4{$secretKey}",
            true
        );
        $regionKey = hash_hmac('sha256', $region, $dateKey, true);
        $serviceKey = hash_hmac('sha256', $service, $regionKey, true);
        return hash_hmac(
            'sha256',
            'aws4_request',
            $serviceKey,
            true
        );
    }
}
