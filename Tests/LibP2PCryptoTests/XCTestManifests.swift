import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(LibP2PCryptoTests.allTests),
    ]
}
#endif
