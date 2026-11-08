package com.roottimer.app;

import com.roottimer.app.IRootCallback;

interface IRootService {
    void runExploit(IRootCallback callback);
    boolean isReady();
    boolean isRooted();
    void destroy();
}
