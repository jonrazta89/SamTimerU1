package com.roottimer.app;

interface IRootCallback {
    void onLog(String line);
    void onComplete(int exitCode, boolean ksuLoaded);
}
