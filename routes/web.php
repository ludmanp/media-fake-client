<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

//Route::get('/', function () {
//    return view('welcome');
//});

Route::any('{uri}', function (Request $request) {
    \Illuminate\Support\Facades\Log::debug('FALLBACK METHOD: ' . $request->method(), [$request->getContent()]);
    \Illuminate\Support\Facades\Log::debug('FALLBACK ROUTE: ' . $request->url(), $request->header());

    if(!app(\App\Services\VerifyAwsV4Signature::class)($request)) {
        return response()->json([
           'message' => 'Invalid Signature'
        ], 401);
    }
    \Illuminate\Support\Facades\Log::debug('VALID SIGNATURE!!!');
})->where('uri', '(.*)');
