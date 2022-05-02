import XCTest

import libp2p_cryptoTests

var tests = [XCTestCaseEntry]()
tests += libp2p_cryptoTests.allTests()
XCTMain(tests)
