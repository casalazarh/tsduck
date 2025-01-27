//----------------------------------------------------------------------------
//
// TSDuck - The MPEG Transport Stream Toolkit
// Copyright (c) 2005-2021, Thierry Lelegard
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//
//----------------------------------------------------------------------------
//
//  TSUnit test suite for class ts::Mutex
//
//  Note that is is difficult to test mutexes without threads. This test suite
//  is partial. More mutex tests are available in test suite ThreadTest.
//
//----------------------------------------------------------------------------

#include "tsMutex.h"
#include "tsunit.h"


//----------------------------------------------------------------------------
// The test fixture
//----------------------------------------------------------------------------

class MutexTest: public tsunit::Test
{
public:
    virtual void beforeTest() override;
    virtual void afterTest() override;

    void testRecursion();

    TSUNIT_TEST_BEGIN(MutexTest);
    TSUNIT_TEST(testRecursion);
    TSUNIT_TEST_END();
};

TSUNIT_REGISTER(MutexTest);


//----------------------------------------------------------------------------
// Initialization.
//----------------------------------------------------------------------------

// Test suite initialization method.
void MutexTest::beforeTest()
{
}

// Test suite cleanup method.
void MutexTest::afterTest()
{
}


//----------------------------------------------------------------------------
// Unitary tests.
//----------------------------------------------------------------------------

void MutexTest::testRecursion()
{
    ts::Mutex mutex;

    TSUNIT_ASSERT(!mutex.release());

    TSUNIT_ASSERT(mutex.acquire());
    TSUNIT_ASSERT(mutex.acquire());
    TSUNIT_ASSERT(mutex.acquire());

    TSUNIT_ASSERT(mutex.release());
    TSUNIT_ASSERT(mutex.release());
    TSUNIT_ASSERT(mutex.release());

    TSUNIT_ASSERT(!mutex.release());
    TSUNIT_ASSERT(!mutex.release());
}
