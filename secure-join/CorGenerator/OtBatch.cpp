#include "OtBatch.h"
#include "CorGenerator.h"
#include "secure-join/Util/match.h"

namespace secJoin
{
    OtBatch::OtBatch(GenState* state, bool sender, oc::Socket&& s, PRNG&& p)
        : Batch(state, std::move(s), std::move(p))
    {
        if (sender)
        {
            mSendRecv.emplace<0>();
        }
        else
        {
            mSendRecv.emplace<1>();
        }
    }

    macoro::task<> OtBatch::RecvOtBatch::recvTask(PRNG& prng, oc::Socket& sock)
    {
        mMsg.resize(mReceiver.mRequestNumOts);
        mChoice.resize(mReceiver.mRequestNumOts);
        assert(mReceiver.hasBaseCors());
        mReceiver.mLpnMultType = oc::MultType::Tungsten;

        return mReceiver.silentReceive(mChoice, mMsg, prng, sock);
    }

    void OtBatch::RecvOtBatch::mock(u64 batchIdx)
    {
        auto s = oc::mAesFixedKey.ecbEncBlock(oc::block(batchIdx, 0));
        osuCrypto::setBytes(mChoice.getSpan<u8>(), s.get<u8>(0));

        for (u32 i = 0; i < mMsg.size(); ++i)
        {
            oc::block m0 = block(i, i);// prng.get();
            oc::block m1 = block(~u64(i), ~u64(i));//prng.get();

            m0 = m0 ^ s;
            m1 = m1 ^ s;
            mMsg.data()[i] = mChoice[i] ? m1 : m0;
        }
    }

    macoro::task<> OtBatch::SendOtBatch::sendTask(PRNG& prng, oc::Socket& sock)
    {
        mMsg2.resize(mSender.mRequestNumOts);
        assert(mSender.hasBaseCors());
        mSender.mLpnMultType = oc::MultType::Tungsten;

        return mSender.silentSend(mMsg2, prng, sock);
    }

    void OtBatch::SendOtBatch::mock(u64 batchIdx)
    {
        auto s = oc::mAesFixedKey.ecbEncBlock(oc::block(batchIdx, 0));
        for (u32 i = 0; i < mMsg2.size(); ++i)
        {
            mMsg2.data()[i][0] = block(i, i);// prng.get();
            mMsg2.data()[i][1] = block(~u64(i), ~u64(i));//prng.get();


            mMsg2.data()[i][0] = mMsg2.data()[i][0] ^ s;
            mMsg2.data()[i][1] = mMsg2.data()[i][1] ^ s;
        }
    }


    void OtBatch::getCor(Cor* c, u64 begin, u64 size)
    {

        mSendRecv | match{
            [&](SendOtBatch& send) {
                if (c->mType != CorType::Ot)
                    std::terminate();

                auto& d = *static_cast<OtSend*>(c);
                d.mMsg = send.mMsg2.subspan(begin, size);
            },
            [&](RecvOtBatch& recv) {
                if (c->mType != CorType::Ot)
                    std::terminate();

                auto& d = *static_cast<OtRecv*>(c);
                auto& msg = recv.mMsg;
                auto& choice = recv.mChoice;

                d.mMsg = msg.subspan(begin, size);

                if (size == choice.size())
                    d.mChoice = std::move(choice);
                else
                {
                    d.mChoice.resize(0);
                    d.mChoice.append(choice, size, begin);
                }
            }
        };
    }

    BaseRequest OtBatch::getBaseRequest()
    {
        BaseRequest r;

        if (mGenState->mMock)
            return r;

        mSendRecv | match{
            [&](SendOtBatch& send) {
                configureTungstenSilentOt(send.mSender, mSize);
                r.mSendSize = send.mSender.baseCount().mBaseOtCount;
            },
            [&](RecvOtBatch& recv) {
                configureTungstenSilentOt(recv.mReceiver, mSize);
                r.mChoice = recv.mReceiver.sampleBaseChoiceBits(mPrng);
            }
        };

        return r;
    }

    void OtBatch::setBase(BaseCor& base)
    {
        if (mGenState->mMock)
            return;

        mSendRecv | match{
            [&](SendOtBatch& send) {
                auto n = send.mSender.baseCount().mBaseOtCount;
                send.mSender.setBaseCors(base.getSendOt(n), {}, {});
            },
            [&](RecvOtBatch& recv) {
                auto n = recv.mReceiver.baseCount().mBaseOtCount;
                auto choices = base.peekRecvOtChoices(n);
                recv.mReceiver.setBaseCors(base.getRecvOt(n), choices, {}, {});
            }
        };
    }

    macoro::task<> OtBatch::getTask(BatchThreadState& threadState) {
            auto t = macoro::task<>{};
            auto msg = std::vector<std::array<block, 2>>{};

        if (mGenState->mMock)
        {
            mSendRecv | match{
                [&](SendOtBatch& send) {
                    send.mMsg2.resize(mSize);
                    send.mock(mIndex);
                },
                [&](RecvOtBatch& recv) {
                    recv.mChoice.resize(mSize);
                    recv.mMsg.resize(mSize);
                    recv.mock(mIndex);
                }
            };
        }
        else
        {
            if (mGenState->mDebug)
            {
                if (mSendRecv.index() == 0)
                {
                    co_await mSock.send(coproto::copy(silentOtRegularPprf(std::get<0>(mSendRecv).mSender).mBaseOTs));

                }
                else
                {

                    msg.resize(std::get<1>(mSendRecv).mReceiver.baseCount().mBaseOtCount);
                    co_await mSock.recv(msg);

                    {
                        auto& recv = std::get<1>(mSendRecv);
                        auto& pprf = silentOtRegularPprf(recv.mReceiver);
                        for (u64 i = 0; i < msg.size(); ++i)
                        {
                            if (pprf.mBaseOTs(i) != msg[i][pprf.mBaseChoices(i)])
                            {
                                std::cout << "OtBatch::getTask() base OTs do not match. " << LOCATION << std::endl;
                                std::terminate();
                            }
                        }
                    }
                }
            }
            t = mSendRecv | match{
                [&](SendOtBatch& send) {

                    send.mSender.mB = std::move(threadState.mB);
                    send.mSender.mEncodeTemp = std::move(threadState.mEncodeTemp);
                    //send.mMsg2 = std::move(threadState.mMsg2);
                    return send.sendTask(mPrng, mSock);
                },
                [&](RecvOtBatch& recv) {
                    recv.mReceiver.mA = std::move(threadState.mA);
                    recv.mReceiver.mEncodeTemp = std::move(threadState.mEncodeTemp);
                    //recv.mChoice = std::move(threadState.mChoice);
                    //recv.mMsg = std::move(threadState.mMsg);
                    return recv.recvTask(mPrng, mSock);
                }
            };

            co_await t;


            mSendRecv | match{
                [&](SendOtBatch& send) {
                    threadState.mB = std::move(send.mSender.mB);
                    threadState.mEncodeTemp = std::move(send.mSender.mEncodeTemp);
                    //threadState.mMsg2 = std::move(send.mMsg2);
                },
                [&](RecvOtBatch& recv) {
                    threadState.mA = std::move(recv.mReceiver.mA);
                    threadState.mEncodeTemp = std::move(recv.mReceiver.mEncodeTemp);
                    //threadState.mChoice = std::move(recv.mChoice);
                    //threadState.mMsg = std::move(recv.mMsg);
                }
            };
        }


        if (mGenState->mDebug)
        {
            if (mSendRecv.index() == 0)
            {
                //std::cout << " checking ot send " << mIndex << std::endl;
                co_await mSock.send(coproto::copy(std::get<0>(mSendRecv).mMsg2));

            }
            else
            {
                //std::cout << " checking ot recv " << mIndex << std::endl;

                msg.resize(std::get<1>(mSendRecv).mMsg.size());
                co_await mSock.recv(msg);

                {
                    auto& recv = std::get<1>(mSendRecv);
                    for (u64 i = 0; i < msg.size(); ++i)
                    {
                        if (recv.mMsg[i] != msg[i][recv.mChoice[i]])
                        {
                            std::cout << "OtBatch::getTask() OTs do not match. " << LOCATION << std::endl;
                            std::terminate();
                        }
                    }
                }
            }
        }


        mCorReady.set();
    }

    void OtBatch::clear()
    {
        mSendRecv | match{
            [&](SendOtBatch& send) {
                send.mMsg2 = {};
            },
            [&](RecvOtBatch& recv) {
                recv.mChoice = {};
                recv.mMsg = {};
            }
        };
    }

    //void OtBatch::mock_(u64 batchIdx)
    //{

    //    mCorReady.set();
    //}


}