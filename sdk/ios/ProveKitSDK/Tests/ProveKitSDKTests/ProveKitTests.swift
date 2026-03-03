import XCTest
@testable import ProveKit

final class ProveKitTests: XCTestCase {
    
    override func setUpWithError() throws {
        try ProveKit.initialize()
    }
    
    // MARK: - Prover Tests
    
    func testProverLoadFromData() throws {
        let pkpURL = fixtureURL("test.pkp")
        let pkpData = try Data(contentsOf: pkpURL)
        
        let prover = try Prover(pkpData: pkpData)
        XCTAssertNotNil(prover)
    }
    
    func testProverLoadFromURL() throws {
        let pkpURL = fixtureURL("test.pkp")
        let prover = try Prover(pkpURL: pkpURL)
        XCTAssertNotNil(prover)
    }
    
    func testProverLoadInvalidData() throws {
        let invalidData = Data([0, 1, 2, 3, 4, 5])
        
        XCTAssertThrowsError(try Prover(pkpData: invalidData)) { error in
            guard case ProveKitError.proverLoadFailed = error else {
                XCTFail("Expected proverLoadFailed error")
                return
            }
        }
    }
    
    // MARK: - Verifier Tests
    
    func testVerifierLoadFromData() throws {
        let pkvURL = fixtureURL("test.pkv")
        let pkvData = try Data(contentsOf: pkvURL)
        
        let verifier = try Verifier(pkvData: pkvData)
        XCTAssertNotNil(verifier)
        XCTAssertFalse(verifier.isConsumed)
    }
    
    func testVerifierLoadFromURL() throws {
        let pkvURL = fixtureURL("test.pkv")
        let verifier = try Verifier(pkvURL: pkvURL)
        XCTAssertNotNil(verifier)
        XCTAssertFalse(verifier.isConsumed)
    }
    
    func testVerifierLoadInvalidData() throws {
        let invalidData = Data([0, 1, 2, 3, 4, 5])
        
        XCTAssertThrowsError(try Verifier(pkvData: invalidData)) { error in
            guard case ProveKitError.verifierLoadFailed = error else {
                XCTFail("Expected verifierLoadFailed error")
                return
            }
        }
    }
    
    // MARK: - Proof Tests
    
    func testProofLoadFromData() throws {
        let proofURL = fixtureURL("test.np")
        let proofData = try Data(contentsOf: proofURL)
        
        let proof = try Proof(serializedData: proofData)
        XCTAssertEqual(proof.serializedData, proofData)
    }
    
    func testProofEquality() throws {
        let proofURL = fixtureURL("test.np")
        let proofData = try Data(contentsOf: proofURL)
        
        let proof1 = try Proof(serializedData: proofData)
        let proof2 = try Proof(serializedData: proofData)
        
        XCTAssertEqual(proof1, proof2)
    }
    
    func testProofEmptyDataThrows() throws {
        XCTAssertThrowsError(try Proof(serializedData: Data())) { error in
            guard case ProveKitError.invalidInput = error else {
                XCTFail("Expected invalidInput error")
                return
            }
        }
    }
    
    // MARK: - Verification Tests
    
    func testVerifyExistingProof() throws {
        let pkvURL = fixtureURL("test.pkv")
        let proofURL = fixtureURL("test.np")
        
        let verifier = try Verifier(pkvURL: pkvURL)
        let proof = try Proof(serializedData: Data(contentsOf: proofURL))
        
        XCTAssertNoThrow(try verifier.verify(proof))
        XCTAssertTrue(verifier.isConsumed)
    }

    /// End-to-end test: Load PKP → Generate Proof → Write to File → Read File → Load PKV → Verify
    func testEndToEndProveWriteReadVerify() throws {
        // =========================================
        // Step 1: Load Prover from PKP file
        // =========================================
        let pkpURL = fixtureURL("test.pkp")
        let prover = try Prover(pkpURL: pkpURL)
        print("✓ Step 1: Loaded prover from \(pkpURL.lastPathComponent)")

        // =========================================
        // Step 2: Generate proof with inputs
        // =========================================
        let proof = try prover.prove(inputs: [
            "plains": [1, 2],
            "a": 1,
            "b": 2,
            "c": 3,
            "d": 5,
            "x": 0,
            "result": "0x0e90c132311e864e0c8bca37976f28579a2dd9436bbc11326e21ec7c00cea5b2"
        ])
        XCTAssertFalse(proof.serializedData.isEmpty)
        print("✓ Step 2: Generated proof (\(proof.serializedData.count) bytes)")

        // =========================================
        // Step 3: Write proof to file
        // =========================================
        let tempDir = FileManager.default.temporaryDirectory
        let proofFileURL = tempDir.appendingPathComponent("swift_test_proof.np")
        try proof.serializedData.write(to: proofFileURL)
        print("✓ Step 3: Wrote proof to \(proofFileURL.lastPathComponent)")

        // =========================================
        // Step 4: Read proof back from file
        // =========================================
        let proofDataFromFile = try Data(contentsOf: proofFileURL)
        let proofFromFile = try Proof(serializedData: proofDataFromFile)
        XCTAssertEqual(proofFromFile.serializedData, proof.serializedData)
        print("✓ Step 4: Read proof from file (\(proofDataFromFile.count) bytes)")

        // =========================================
        // Step 5: Load Verifier from PKV file
        // =========================================
        let pkvURL = fixtureURL("test.pkv")
        let verifier = try Verifier(pkvURL: pkvURL)
        print("✓ Step 5: Loaded verifier from \(pkvURL.lastPathComponent)")

        // =========================================
        // Step 6: Verify the proof read from file
        // =========================================
        try verifier.verify(proofFromFile)
        XCTAssertTrue(verifier.isConsumed)
        print("✓ Step 6: Proof verified successfully!")

        // Cleanup
        try? FileManager.default.removeItem(at: proofFileURL)

        print("")
        print("=== SWIFT END-TO-END TEST PASSED ===")
        print("  PKP loaded: \(pkpURL.lastPathComponent)")
        print("  PKV loaded: \(pkvURL.lastPathComponent)")
        print("  Proof generated, written to file, read back, and verified!")
    }
    
    func testVerifierConsumedThrows() throws {
        let pkvURL = fixtureURL("test.pkv")
        let proofURL = fixtureURL("test.np")
        
        let verifier = try Verifier(pkvURL: pkvURL)
        let proof = try Proof(serializedData: Data(contentsOf: proofURL))
        
        try verifier.verify(proof)
        
        XCTAssertThrowsError(try verifier.verify(proof)) { error in
            guard case ProveKitError.verifierConsumed = error else {
                XCTFail("Expected verifierConsumed error")
                return
            }
        }
    }
    
    // MARK: - Helpers
    
    private func fixtureURL(_ filename: String) -> URL {
        let bundle = Bundle.module
        guard let url = bundle.url(forResource: filename, withExtension: nil, subdirectory: "Fixtures") else {
            fatalError("Fixture not found: \(filename)")
        }
        return url
    }
}
