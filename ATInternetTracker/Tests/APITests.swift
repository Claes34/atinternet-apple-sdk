import Foundation

import XCTest
@testable import Tracker

class MockStore: SimpleStorageProtocol {
    var store: AnyObject? = nil
    func getByName(name: String) -> AnyObject? {return store}
    func saveByName(config: AnyObject, name: String) -> Bool {store = config; return true}
}

class MockNetwork: SimpleNetworkService {
    func getURL(request: MappingRequest, retryCount: Int) {
        request.onLoaded(ATJSON(["timestamp":123456]))
    }
}

class APITests: XCTestCase {

    override func setUp() {
        /**
        We clean up the queue manager before any test
        Since we can't clean manually, we have to cancel everything + wait all op to finish/be canceled
        */
        super.setUp()
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testApiUrlGeneration() {
        let api = ApiS3Client( token: "6aed0903eda8c21f79febd5dc06a530cb3ef9c132414124afbd76e50f7074f9f",
                              version: "1.1",
                              store: MockStore(),
                              networkService: MockNetwork())
        let url = api.getMappingURL()

        XCTAssertEqual(url, NSURL(string: "https://8me4zn67yd.execute-api.eu-west-1.amazonaws.com/prod/token/6aed0903eda8c21f79febd5dc06a530cb3ef9c132414124afbd76e50f7074f9f/version/1.1"))
    }

    func testFetchMappingIfNoMappingInMemory() {
        let exp = expectationWithDescription("async")
        
        let api = ApiS3Client(token: "X", version: "1.0", store: MockStore(), networkService: MockNetwork())
        api.fetchMapping({(apiMapping: ATJSON?) in
            XCTAssertNotNil(apiMapping)
            exp.fulfill()
        })
        
        self.waitForExpectationsWithTimeout(5.0) { (err:NSError?) in
            if let error = err {
                print("timeout error \(error)")
            }
        }
    }
    
    func testFetchMappingIfCheckSumDiffer() {
        let exp = expectationWithDescription("async")
        let ts = "123"
        let api = ApiS3Client(token: "X", version: "1.0", store: MockStore(), networkService: MockNetwork())
        let fakeAPI: ATJSON = ATJSON(["timestamp":ts])
        api.saveSmartSDKMapping(fakeAPI)
        api.fetchMapping({ (mapping:ATJSON?) in
            XCTAssertNotEqual(mapping!["timestamp"].string, ts)
            exp.fulfill()
        })
        self.waitForExpectationsWithTimeout(5.0) { (err:NSError?) in
            if let error = err {
                print("timeout error \(error)")
            }
        }
    }
    
    func testDontFetchMappingIfCheckSumOk() {
        let exp = expectationWithDescription("async")
        let api = ApiS3Client(token: "X", version: "1.0", store: MockStore(), networkService: MockNetwork())
        api.fetchMapping({ (mapping:ATJSON?) in
            api.saveSmartSDKMapping(mapping!)
            api.fetchMapping({ (mapping:ATJSON?) in
                exp.fulfill()
            })
        })
        self.waitForExpectationsWithTimeout(5.0) { (err:NSError?) in
            if let error = err {
                print("timeout error \(error)")
            }
        }
    }
}
