import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(libp2p_cryptoTests.allTests),
    ]
}
#endif
