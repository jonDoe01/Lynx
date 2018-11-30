#ifndef BITCOIN_STATUS_SENDER_H
#define BITCOIN_STATUS_SENDER_H


namespace StatusSender
{
    void start();
    void stop();
    bool isRunning();
    bool appInit();
};

#endif // BITCOIN_STATUS_SENDER_H
