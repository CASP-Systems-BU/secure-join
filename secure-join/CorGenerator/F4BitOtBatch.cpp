#include "F4BitOtBatch.h"
#include "CorGenerator.h"
#include "secure-join/Util/match.h"
namespace secJoin
{



	F4BitOtBatch::F4BitOtBatch(GenState* state, bool sender, oc::Socket&& s, PRNG&& p)
		: Batch(state, std::move(s), std::move(p))
		, mSendRecv(std::in_place_type_t<SendBatch>{})
	{
		if (sender)
			mSendRecv.emplace<0>();
		else
			mSendRecv.emplace<1>();
	}

	void F4BitOtBatch::getCor(Cor* c, u64 begin, u64 size)
	{
		if (c->mType != CorType::F4BitOt)
			std::terminate();


		//auto& d = *static_cast<BinOle*>(c);
		assert(begin % 128 == 0);
		assert(size % 128 == 0);
		//d.mAdd = mAdd.subspan(begin / 128, size / 128);
		//d.mMult = mMult.subspan(begin / 128, size / 128);

		mSendRecv | match{
			[&](SendBatch& send) {
				auto& d = *static_cast<F4BitOtSend*>(c);
				for (u64 i = 0; i < 4; ++i)
					d.mOts[i] = send.mOts[i].subspan(begin / 128, size / 128);
			},

			[&](RecvBatch& recv) {
				auto& d = *static_cast<F4BitOtRecv*>(c);
				d.mOts = recv.mOts.subspan(begin / 128, size / 128);
				d.mChoiceLsb = recv.mChoiceLsb.subspan(begin / 128, size / 128);
				d.mChoiceMsb = recv.mChoiceMsb.subspan(begin / 128, size / 128);
			}
		};
	}

	BaseRequest F4BitOtBatch::getBaseRequest()
	{
		BaseRequest r;

		if (mGenState->mMock)
			return r;

		mSendRecv | match{
			[&](SendBatch& send) {
				send.mSender.configure(mSize);
				r.mSendSize = send.mSender.silentBaseOtCount();
				r.mSendVoleSize = send.mSender.baseVoleCount();
			},

			[&](RecvBatch& recv) {
				recv.mReceiver.configure(mSize);
				r.mChoice = recv.mReceiver.sampleBaseChoiceBits(mPrng);
				r.mVoleChoice = recv.mReceiver.sampleBaseVoleVals(mPrng);
			}
		};
		return r;
	}

	void F4BitOtBatch::setBase(BaseCor& base)
	{

		if (mGenState->mMock)
			return;

		mSendRecv | match{
			[&](SendBatch& send) {
				send.mDelta = base.mVoleDelta;
				send.mSender.setSilentBaseOts(
					base.getSendOt(send.mSender.silentBaseOtCount()),
					base.getSendVole(send.mSender.baseVoleCount()));
			},
			[&](RecvBatch& recv) {
				recv.mReceiver.setSilentBaseOts(
					base.getRecvOt(recv.mReceiver.silentBaseOtCount()),
					base.getRecvVole(recv.mReceiver.baseVoleCount()));
			}
		};
	}

	macoro::task<> F4BitOtBatch::getTask(BatchThreadState& threadState)
	{
		return mSendRecv | match{
			[&](SendBatch& send) {
				   return send.sendTask(mGenState, mIndex, mSize, mPrng, mSock, mCorReady, threadState);
			},
			[&](RecvBatch& recv) {
				  return  recv.recvTask(mGenState,mIndex, mSize, mPrng, mSock, mCorReady, threadState);
			}
		};
	}

	//void ThreeOleBatch::mock(u64 batchIdx)
	//{

	//    mCorReady.set();

	//}
	void F4BitOtBatch::SendBatch::mock(u64 batchIdx, u64 n)
	{
		//memset(add, 0);
		//memset(mult, 0);
		//return;
		assert(n % 128 == 0);
		auto  m = n / 128;
		mOts[0].resize(m);
		mOts[1].resize(m);
		mOts[2].resize(m);
		mOts[3].resize(m);

		if (1)
		{
			for (u64 j = 0; j < 4; ++j)
				memset<block>(mOts[j], 0);
			return;
		}

		//auto m = add.size();
		auto m8 = m / 8 * 8;
		oc::block mm8(4532453452, 43254534);
		oc::block mm = oc::mAesFixedKey.ecbEncBlock(oc::block(batchIdx, 0));
		block diff[4];
		for (u64 i = 0; i < 4; ++i)
			diff[i] = block(409890897878905234 * i + 45234523, 5234565646423452 * i + 409890897878905234);
		u64 i = 0;
		while (i < m8)
		{
			mOts[0].data()[i + 0] = mm;
			mOts[0].data()[i + 1] = mm >> 1 | mm << 1;
			mOts[0].data()[i + 2] = mm >> 2 | mm << 2;
			mOts[0].data()[i + 3] = mm >> 3 | mm << 3;
			mOts[0].data()[i + 4] = mm >> 4 | mm << 4;
			mOts[0].data()[i + 5] = mm >> 5 | mm << 5;
			mOts[0].data()[i + 6] = mm >> 6 | mm << 6;
			mOts[0].data()[i + 7] = mm >> 7 | mm << 7;

			for (u64 j = 1; j < 4; ++j)
			{
				mOts[j].data()[i + 0] = mOts[0].data()[i + 0] ^ diff[j];
				mOts[j].data()[i + 1] = mOts[0].data()[i + 1] ^ diff[j];
				mOts[j].data()[i + 2] = mOts[0].data()[i + 2] ^ diff[j];
				mOts[j].data()[i + 3] = mOts[0].data()[i + 3] ^ diff[j];
				mOts[j].data()[i + 4] = mOts[0].data()[i + 4] ^ diff[j];
				mOts[j].data()[i + 5] = mOts[0].data()[i + 5] ^ diff[j];
				mOts[j].data()[i + 6] = mOts[0].data()[i + 6] ^ diff[j];
				mOts[j].data()[i + 7] = mOts[0].data()[i + 7] ^ diff[j];
				diff[j] = (diff[j] + diff[j]) ^ block(342134123, 213412341);
			}

			//for(u64 ii = i; ii < i+8; ++ii)
			//{
			//	std::cout << "s ots " << ii << " ";
			//	for (u64 j = 0; j < 4; ++j)
			//		std::cout << mOts[j][ii] << " ";
			//	std::cout << std::endl;
			//}

			mm += mm8;
			i += 8;
		}
		for (; i < m; ++i)
		{
			mOts[0][i] = mm;
			for (u64 j = 1; j < 4; ++j)
			{
				mOts[j][i] = mOts[0][i] ^ diff[j];
			}

			//std::cout << "s diff " << i << " ";
			//for (u64 j = 0; j < 4; ++j)
			//	std::cout << diff[j] << " ";
			//std::cout << std::endl;
			//std::cout << "s ots " << i << " ";
			//for (u64 j = 0; j < 4; ++j)
			//	std::cout << mOts[j][i] << " ";
			//std::cout << std::endl;
		}
	}

	void F4BitOtBatch::RecvBatch::mock(u64 batchIdx, u64 n)
	{

		//memset(add, 0);
		//memset(mult, 0);
		//return;
		//throw RTE_LOC;
		assert(n % 128 == 0);
		auto  m = n / 128;
		mOts.resize(m);
		mChoiceLsb.resize(m);
		mChoiceMsb.resize(m);
		if (1)
		{
			memset<block>(mOts, 0);
			memset<block>(mChoiceLsb, 0);
			memset<block>(mChoiceMsb, 0);
			return;
		}

		//auto m = add.size();
		auto m8 = m / 8 * 8;
		oc::block mm8(4532453452, 43254534);
		oc::block mm = oc::mAesFixedKey.ecbEncBlock(oc::block(batchIdx, 0));
		block diff[4];
		for (u64 i = 0; i < 4; ++i)
			diff[i] = block(409890897878905234 * i + 45234523, 5234565646423452 * i + 409890897878905234);
		u64 i = 0;
		std::array< std::array<block, 8>, 4> ots;

		while (i < m8)
		{

			ots[0].data()[0] = mm;
			ots[0].data()[1] = mm >> 1 | mm << 1;
			ots[0].data()[2] = mm >> 2 | mm << 2;
			ots[0].data()[3] = mm >> 3 | mm << 3;
			ots[0].data()[4] = mm >> 4 | mm << 4;
			ots[0].data()[5] = mm >> 5 | mm << 5;
			ots[0].data()[6] = mm >> 6 | mm << 6;
			ots[0].data()[7] = mm >> 7 | mm << 7;

			mOts.data()[i + 0] = ots[0][0] & (~mChoiceMsb[i + 0] & ~mChoiceLsb[i + 0]);
			mOts.data()[i + 1] = ots[0][1] & (~mChoiceMsb[i + 1] & ~mChoiceLsb[i + 1]);
			mOts.data()[i + 2] = ots[0][2] & (~mChoiceMsb[i + 2] & ~mChoiceLsb[i + 2]);
			mOts.data()[i + 3] = ots[0][3] & (~mChoiceMsb[i + 3] & ~mChoiceLsb[i + 3]);
			mOts.data()[i + 4] = ots[0][4] & (~mChoiceMsb[i + 4] & ~mChoiceLsb[i + 4]);
			mOts.data()[i + 5] = ots[0][5] & (~mChoiceMsb[i + 5] & ~mChoiceLsb[i + 5]);
			mOts.data()[i + 6] = ots[0][6] & (~mChoiceMsb[i + 6] & ~mChoiceLsb[i + 6]);
			mOts.data()[i + 7] = ots[0][7] & (~mChoiceMsb[i + 7] & ~mChoiceLsb[i + 7]);


			for (u64 j = 1; j < 4; ++j)
			{
				ots[j].data()[0] = ots[0].data()[0] ^ diff[j];
				ots[j].data()[1] = ots[0].data()[1] ^ diff[j];
				ots[j].data()[2] = ots[0].data()[2] ^ diff[j];
				ots[j].data()[3] = ots[0].data()[3] ^ diff[j];
				ots[j].data()[4] = ots[0].data()[4] ^ diff[j];
				ots[j].data()[5] = ots[0].data()[5] ^ diff[j];
				ots[j].data()[6] = ots[0].data()[6] ^ diff[j];
				ots[j].data()[7] = ots[0].data()[7] ^ diff[j];
				diff[j] = (diff[j] + diff[j]) ^ block(342134123, 213412341);

				auto mLsb = block(~0ull * !bool(j & 1), ~0ull * !bool(j & 1));
				auto mMsb = block(~0ull * !bool(j & 2), ~0ull * !bool(j & 2));
				mOts.data()[i + 0] ^= ots[j][0] & ((mMsb ^ mChoiceMsb[i + 0]) & (mLsb ^ mChoiceLsb[i + 0]));
				mOts.data()[i + 1] ^= ots[j][1] & ((mMsb ^ mChoiceMsb[i + 1]) & (mLsb ^ mChoiceLsb[i + 1]));
				mOts.data()[i + 2] ^= ots[j][2] & ((mMsb ^ mChoiceMsb[i + 2]) & (mLsb ^ mChoiceLsb[i + 2]));
				mOts.data()[i + 3] ^= ots[j][3] & ((mMsb ^ mChoiceMsb[i + 3]) & (mLsb ^ mChoiceLsb[i + 3]));
				mOts.data()[i + 4] ^= ots[j][4] & ((mMsb ^ mChoiceMsb[i + 4]) & (mLsb ^ mChoiceLsb[i + 4]));
				mOts.data()[i + 5] ^= ots[j][5] & ((mMsb ^ mChoiceMsb[i + 5]) & (mLsb ^ mChoiceLsb[i + 5]));
				mOts.data()[i + 6] ^= ots[j][6] & ((mMsb ^ mChoiceMsb[i + 6]) & (mLsb ^ mChoiceLsb[i + 6]));
				mOts.data()[i + 7] ^= ots[j][7] & ((mMsb ^ mChoiceMsb[i + 7]) & (mLsb ^ mChoiceLsb[i + 7]));

			}
			//for (u64 ii = i; ii < i + 8; ++ii)
			//{
			//	std::cout << "r ots " << ii << " ";
			//	for (u64 j = 0; j < 4; ++j)
			//		std::cout << ots[j][ii] << " ";
			//	std::cout << std::endl;
			//}

			mm += mm8;
			i += 8;
		}
		for (; i < m; ++i)
		{
			ots[0][0] = mm;
			mOts[i] = ots[0][0] & (~mChoiceMsb[i + 0] & ~mChoiceLsb[i + 0]);


			for (u64 j = 1; j < 4; ++j)
			{
				ots[j][0] = ots[0][0] ^ diff[j];

				auto mLsb = block(~0ull * !bool(j & 1), ~0ull * !bool(j & 1));
				auto mMsb = block(~0ull * !bool(j & 2), ~0ull * !bool(j & 2));
				mOts[i] ^= ots[j][0] & ((mMsb ^ mChoiceMsb[i]) & (mLsb ^ mChoiceLsb[i]));
			}

			//std::cout << "r diff " << i << " ";
			//for (u64 j = 0; j < 4; ++j)
			//	std::cout << diff[j] << " ";
			//std::cout << std::endl;
			//std::cout << "r ots " << i << " ";
			//for (u64 j = 0; j < 4; ++j)
			//	std::cout << ots[j][0] << " ";
			//std::cout << std::endl;

		}
	}


	macoro::task<>  F4BitOtBatch::RecvBatch::recvTask(
		GenState* state,
		u64 batchIdx,
		u64 size,
		PRNG& prng,
		oc::Socket& sock,
		macoro::async_manual_reset_event& corReady,
		BatchThreadState& threadState)
	{
		//MC_BEGIN(macoro::task<>, this, state, batchIdx, size, &prng,
			//&sock, &corReady, &threadState,
			auto baseSend = std::vector<std::array<block, 2>>{};
			auto baseB = std::vector<block>{};
			auto baseDelta = block{};
		//);

		if (state->mMock)
		{
			mock(batchIdx, size);
		}
		else
		{

			if (state->mDebug)
			{
				baseSend.resize(mReceiver.silentBaseOtCount());
				baseB.resize(mReceiver.baseVoleCount());
				co_await sock.recv(baseSend);
				co_await sock.recv(baseB);
				co_await sock.recv(baseDelta);

				{
					for (u64 i = 0; i < baseSend.size(); ++i)
					{
						if (mReceiver.mGen.mBaseOTs(i) != baseSend[i][mReceiver.mGen.mBaseChoices(i)])
						{
							std::cout << "F4RecvOleBatch::getTask() base OTs do not match. " << LOCATION << std::endl;
							std::terminate();
						}
					}


					for (u64 i = 0; i < baseB.size(); ++i)
					{
						auto ci = mReceiver.mBaseC[i];
						auto ai = mReceiver.mBaseA[i] & block(~0ull, ~3ull);
						auto bi = baseB[i] & block(~0ull, ~3ull);

						block exp;
						CoeffCtxGF4{}.mul(exp, baseDelta & block(~0ull, ~3ull), ci);
						exp = exp ^ bi;

						if (ai != exp)
						{
							std::cout << "F4RecvOleBatch::getTask() base VOLE do not match. " << LOCATION << std::endl;
							std::cout << "ai  " << ai << std::endl;
							std::cout << "exp " << exp << std::endl;
							std::terminate();
						}
					}

				}
			}

			assert(mReceiver.mGen.hasBaseOts());
			mReceiver.mMultType = oc::MultType::Tungsten;
			mReceiver.mA = std::move(threadState.mA);
			mReceiver.mEncodeTemp = std::move(threadState.mEncodeTemp);
			mReceiver.mGen.mTempBuffer = std::move(threadState.mPprfTemp);
			mReceiver.mGen.mEagerSend = false;

			mReceiver.mDebug = state->mDebug;

			 co_await mReceiver.silentReceiveInplace(mReceiver.mRequestSize, prng, sock);


			compressRecver(mReceiver.mA);

			threadState.mA = std::move(mReceiver.mA);
			threadState.mEncodeTemp = std::move(mReceiver.mEncodeTemp);
			threadState.mPprfTemp = std::move(mReceiver.mGen.mTempBuffer);

		}

		corReady.set();
	}

	macoro::task<>  F4BitOtBatch::SendBatch::sendTask(
		GenState* state,
		u64 batchIdx,
		u64 size,
		PRNG& prng,
		oc::Socket& sock,
		macoro::async_manual_reset_event& corReady,
		BatchThreadState& threadState)
	{

		if (state->mMock)
		{
			mock(batchIdx, size);
		}
		else
		{

			if (state->mDebug)
			{
				co_await sock.send(coproto::copy(mSender.mGen.mBaseOTs));
				co_await sock.send(mSender.mBaseB);
				co_await sock.send(mDelta);

			}

			assert(mSender.mGen.hasBaseOts());
			mSender.mMultType = oc::MultType::Tungsten;


			mSender.mB = std::move(threadState.mB);
			mSender.mEncodeTemp = std::move(threadState.mEncodeTemp);
			mSender.mGen.mTempBuffer = std::move(threadState.mPprfTemp);
			mSender.mGen.mEagerSend = false;

			mSender.mDebug = state->mDebug;

			co_await mSender.silentSendInplace(mDelta, mSender.mRequestSize, prng, sock);


			compressSender(mSender.mB);

			threadState.mB = std::move(mSender.mB);
			threadState.mEncodeTemp = std::move(mSender.mEncodeTemp);
			threadState.mPprfTemp = std::move(mSender.mGen.mTempBuffer);
		}


		corReady.set();
	}



	// the first two bits of A is the choice bit of the VOLE.

	void F4BitOtBatch::RecvBatch::compressRecver(
		span<oc::block> A)
	{
		mOts.resize(A.size());
		mChoiceLsb.resize(A.size());
		mChoiceMsb.resize(A.size());
		auto aIter16 = (u16*)mOts.data();
		auto lsbIter8 = (u8*)mChoiceLsb.data();
		auto msbIter8 = (u8*)mChoiceMsb.data();

		auto shuffle = std::array<block, 16>{};
		memset(shuffle.data(), 1 << 7, sizeof(*shuffle.data()) * shuffle.size());
		for (u64 i = 0; i < 16; ++i)
			shuffle[i].set<u8>(i, 0);

		auto OneBlock = block(1);
		auto TwoBlock = block(2);
		block mask = block(~0ull, ~3ull);

		auto m = &A[0];

		for (u64 i = 0; i < A.size(); i += 16)
		{
			u32 lsb[8], msb[8];
			for (u64 j = 0; j < 2; ++j)
			{
				// extract the choice bit from the LSB of m
				_mm_storeu_si32(&lsb[0], m[0] & OneBlock);
				_mm_storeu_si32(&lsb[1], m[1] & OneBlock);
				_mm_storeu_si32(&lsb[2], m[2] & OneBlock);
				_mm_storeu_si32(&lsb[3], m[3] & OneBlock);
				_mm_storeu_si32(&lsb[4], m[4] & OneBlock);
				_mm_storeu_si32(&lsb[5], m[5] & OneBlock);
				_mm_storeu_si32(&lsb[6], m[6] & OneBlock);
				_mm_storeu_si32(&lsb[7], m[7] & OneBlock);

				assert(lsb[0] == (m[0].get<u64>(0) & 1));

				// pack the choice bits.
				*lsbIter8++ =
					lsb[0] ^
					(lsb[1] << 1) ^
					(lsb[2] << 2) ^
					(lsb[3] << 3) ^
					(lsb[4] << 4) ^
					(lsb[5] << 5) ^
					(lsb[6] << 6) ^
					(lsb[7] << 7);

				// extract the choice bit from the MSB of m

				_mm_storeu_si32(&msb[0], m[0] & TwoBlock);
				_mm_storeu_si32(&msb[1], m[1] & TwoBlock);
				_mm_storeu_si32(&msb[2], m[2] & TwoBlock);
				_mm_storeu_si32(&msb[3], m[3] & TwoBlock);
				_mm_storeu_si32(&msb[4], m[4] & TwoBlock);
				_mm_storeu_si32(&msb[5], m[5] & TwoBlock);
				_mm_storeu_si32(&msb[6], m[6] & TwoBlock);
				_mm_storeu_si32(&msb[7], m[7] & TwoBlock);

				assert(msb[0] == (m[0].get<u64>(0) & 2));


				// pack the choice bits.
				*msbIter8++ =
					(msb[0] >> 1) ^
					(msb[1]) ^
					(msb[2] << 1) ^
					(msb[3] << 2) ^
					(msb[4] << 3) ^
					(msb[5] << 4) ^
					(msb[6] << 5) ^
					(msb[7] << 6);

				// mask of the choice bits which is stored in the LSB
				m[0] = m[0] & mask;
				m[1] = m[1] & mask;
				m[2] = m[2] & mask;
				m[3] = m[3] & mask;
				m[4] = m[4] & mask;
				m[5] = m[5] & mask;
				m[6] = m[6] & mask;
				m[7] = m[7] & mask;

				oc::mAesFixedKey.hashBlocks<8>(m, m);

				m += 8;


			}
			m -= 16;

			block a00 = _mm_shuffle_epi8(m[0], shuffle[0]);
			block a01 = _mm_shuffle_epi8(m[1], shuffle[1]);
			block a02 = _mm_shuffle_epi8(m[2], shuffle[2]);
			block a03 = _mm_shuffle_epi8(m[3], shuffle[3]);
			block a04 = _mm_shuffle_epi8(m[4], shuffle[4]);
			block a05 = _mm_shuffle_epi8(m[5], shuffle[5]);
			block a06 = _mm_shuffle_epi8(m[6], shuffle[6]);
			block a07 = _mm_shuffle_epi8(m[7], shuffle[7]);
			block a08 = _mm_shuffle_epi8(m[8], shuffle[8]);
			block a09 = _mm_shuffle_epi8(m[9], shuffle[9]);
			block a10 = _mm_shuffle_epi8(m[10], shuffle[10]);
			block a11 = _mm_shuffle_epi8(m[11], shuffle[11]);
			block a12 = _mm_shuffle_epi8(m[12], shuffle[12]);
			block a13 = _mm_shuffle_epi8(m[13], shuffle[13]);
			block a14 = _mm_shuffle_epi8(m[14], shuffle[14]);
			block a15 = _mm_shuffle_epi8(m[15], shuffle[15]);

			a00 = a00 ^ a08;
			a01 = a01 ^ a09;
			a02 = a02 ^ a10;
			a03 = a03 ^ a11;
			a04 = a04 ^ a12;
			a05 = a05 ^ a13;
			a06 = a06 ^ a14;
			a07 = a07 ^ a15;

			a00 = a00 ^ a04;
			a01 = a01 ^ a05;
			a02 = a02 ^ a06;
			a03 = a03 ^ a07;

			a00 = a00 ^ a02;
			a01 = a01 ^ a03;

			a00 = a00 ^ a01;

			a00 = _mm_slli_epi16(a00, 7);

			u16 ap = _mm_movemask_epi8(a00);

			*aIter16++ = ap;
			m += 16;

		}
	}


	void F4BitOtBatch::SendBatch::compressSender(
		span<oc::block> B)
	{
		for (u64 i = 0; i < 4; ++i)
			mOts[i].resize(B.size());

		std::array<u16*, 4> iters
		{
			(u16*)mOts[0].data(),
			(u16*)mOts[1].data(),
			(u16*)mOts[2].data(),
			(u16*)mOts[3].data()
		};
		//auto bIter16 = (u16*)add.data();
		//auto aIter16 = (u16*)mult.data();
		//if (add.size() * 128 != B.size())
		//    throw RTE_LOC;
		//if (mult.size() * 128 != B.size())
		//    throw RTE_LOC;
		using block = oc::block;

		auto shuffle = std::array<block, 16>{};
		memset(shuffle.data(), 1 << 7, sizeof(*shuffle.data()) * shuffle.size());
		for (u64 i = 0; i < 16; ++i)
			shuffle[i].set<u8>(i, 0);

		std::array<block, 16> sendMsg;
		//auto m = B.data();

		block mask = block(~0ull, ~3ull);;
		std::array<block, 4> deltas;
		deltas[0] = block(0, 0);
		deltas[1] = mDelta & mask;
		CoeffCtxGF4{}.mul(deltas[2], deltas[1], F4{ 2 });
		CoeffCtxGF4{}.mul(deltas[3], deltas[1], F4{ 3 });

		for (u64 i = 0; i < B.size(); i += 16)
		{
			for (u64 b = 0; b < 4; ++b)
			{
				auto s = sendMsg.data();
				auto m = B.data() + i;

				switch (b)
				{
				case 0:
				{
					for (u64 j = 0; j < 2; ++j)
					{
						assert((m[0].get<u64>(0) & 3) == 0);

						m[0] = m[0] & mask;
						m[1] = m[1] & mask;
						m[2] = m[2] & mask;
						m[3] = m[3] & mask;
						m[4] = m[4] & mask;
						m[5] = m[5] & mask;
						m[6] = m[6] & mask;
						m[7] = m[7] & mask;

						oc::mAesFixedKey.hashBlocks<8>(m, s);

						s += 8;
						m += 8;
					}

					break;
				}
				case 1:
				case 2:
				case 3:
					for (u64 j = 0; j < 2; ++j)
					{
						s[0] = m[0] ^ deltas[b];
						s[1] = m[1] ^ deltas[b];
						s[2] = m[2] ^ deltas[b];
						s[3] = m[3] ^ deltas[b];
						s[4] = m[4] ^ deltas[b];
						s[5] = m[5] ^ deltas[b];
						s[6] = m[6] ^ deltas[b];
						s[7] = m[7] ^ deltas[b];

						oc::mAesFixedKey.hashBlocks<8>(s, s);

						s += 8;
						m += 8;
					}
					break;
				default:
					assert(0);
					//__assume(0);
					break;
				}

				block a00 = _mm_shuffle_epi8(sendMsg[0], shuffle[0]);
				block a01 = _mm_shuffle_epi8(sendMsg[1], shuffle[1]);
				block a02 = _mm_shuffle_epi8(sendMsg[2], shuffle[2]);
				block a03 = _mm_shuffle_epi8(sendMsg[3], shuffle[3]);
				block a04 = _mm_shuffle_epi8(sendMsg[4], shuffle[4]);
				block a05 = _mm_shuffle_epi8(sendMsg[5], shuffle[5]);
				block a06 = _mm_shuffle_epi8(sendMsg[6], shuffle[6]);
				block a07 = _mm_shuffle_epi8(sendMsg[7], shuffle[7]);
				block a08 = _mm_shuffle_epi8(sendMsg[8], shuffle[8]);
				block a09 = _mm_shuffle_epi8(sendMsg[9], shuffle[9]);
				block a10 = _mm_shuffle_epi8(sendMsg[10], shuffle[10]);
				block a11 = _mm_shuffle_epi8(sendMsg[11], shuffle[11]);
				block a12 = _mm_shuffle_epi8(sendMsg[12], shuffle[12]);
				block a13 = _mm_shuffle_epi8(sendMsg[13], shuffle[13]);
				block a14 = _mm_shuffle_epi8(sendMsg[14], shuffle[14]);
				block a15 = _mm_shuffle_epi8(sendMsg[15], shuffle[15]);

				a00 = a00 ^ a08;
				a01 = a01 ^ a09;
				a02 = a02 ^ a10;
				a03 = a03 ^ a11;
				a04 = a04 ^ a12;
				a05 = a05 ^ a13;
				a06 = a06 ^ a14;
				a07 = a07 ^ a15;

				a00 = a00 ^ a04;
				a01 = a01 ^ a05;
				a02 = a02 ^ a06;
				a03 = a03 ^ a07;

				a00 = a00 ^ a02;
				a01 = a01 ^ a03;

				a00 = a00 ^ a01;

				a00 = _mm_slli_epi16(a00, 7);

				u16 ap = _mm_movemask_epi8(a00);

				assert(iters[b] < (u16*)(mOts[b].data() + mOts[b].size()));
				*iters[b]++ = ap;
			}
		}
	}


}