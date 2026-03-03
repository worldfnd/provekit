import Foundation
import ProveKitFFI

enum FFIBridge {
    
    private static var isInitialized = false
    
    static func initialize() throws {
        guard !isInitialized else { return }
        
        let result = pk_init()
        guard result == 0 else {
            throw ProveKitError.ffiError(code: result, message: "Failed to initialize ProveKit")
        }
        isInitialized = true
    }
    
    static func ensureInitialized() throws {
        guard isInitialized else {
            throw ProveKitError.notInitialized
        }
    }
    
    // MARK: - Prover Operations
    
    static func loadProver(from data: Data) throws -> OpaquePointer {
        try ensureInitialized()
        
        var errorPtr: UnsafeMutablePointer<CChar>? = nil
        
        let handle = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> OpaquePointer? in
            guard let baseAddress = bytes.baseAddress else { return nil }
            return pk_prover_load(
                baseAddress.assumingMemoryBound(to: UInt8.self),
                bytes.count,
                &errorPtr
            )
        }
        
        guard let proverHandle = handle else {
            let message = extractAndFreeError(errorPtr)
            throw ProveKitError.proverLoadFailed(message ?? "Unknown error")
        }
        
        return proverHandle
    }
    
    static func loadProver(from path: String) throws -> OpaquePointer {
        try ensureInitialized()
        
        var errorPtr: UnsafeMutablePointer<CChar>? = nil
        
        guard let handle = pk_prover_load_file(path, &errorPtr) else {
            let message = extractAndFreeError(errorPtr)
            throw ProveKitError.proverLoadFailed(message ?? "Unknown error")
        }
        
        return handle
    }
    
    static func prove(prover: OpaquePointer, inputs: [String: Any]) throws -> Data {
        var errorPtr: UnsafeMutablePointer<CChar>? = nil
        var proofPtr: UnsafeMutablePointer<UInt8>? = nil
        var proofLen: Int = 0
        
        let jsonData = try JSONSerialization.data(withJSONObject: inputs)
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw ProveKitError.serializationFailed("Failed to encode inputs as JSON")
        }
        
        let result = pk_prover_prove(
            prover,
            jsonString,
            &proofPtr,
            &proofLen,
            &errorPtr
        )
        
        guard result == 0, let proof = proofPtr else {
            let message = extractAndFreeError(errorPtr)
            throw ProveKitError.fromFFI(code: result, message: message)
        }
        
        defer { pk_free_bytes(proof, proofLen) }
        return Data(bytes: proof, count: proofLen)
    }
    
    static func freeProver(_ handle: OpaquePointer) {
        pk_prover_free(handle)
    }
    
    // MARK: - Verifier Operations
    
    static func loadVerifier(from data: Data) throws -> OpaquePointer {
        try ensureInitialized()
        
        var errorPtr: UnsafeMutablePointer<CChar>? = nil
        
        let handle = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> OpaquePointer? in
            guard let baseAddress = bytes.baseAddress else { return nil }
            return pk_verifier_load(
                baseAddress.assumingMemoryBound(to: UInt8.self),
                bytes.count,
                &errorPtr
            )
        }
        
        guard let verifierHandle = handle else {
            let message = extractAndFreeError(errorPtr)
            throw ProveKitError.verifierLoadFailed(message ?? "Unknown error")
        }
        
        return verifierHandle
    }
    
    static func loadVerifier(from path: String) throws -> OpaquePointer {
        try ensureInitialized()
        
        var errorPtr: UnsafeMutablePointer<CChar>? = nil
        
        guard let handle = pk_verifier_load_file(path, &errorPtr) else {
            let message = extractAndFreeError(errorPtr)
            throw ProveKitError.verifierLoadFailed(message ?? "Unknown error")
        }
        
        return handle
    }
    
    static func verify(verifier: OpaquePointer, proof: Data) throws {
        var errorPtr: UnsafeMutablePointer<CChar>? = nil
        
        let result = proof.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int32 in
            guard let baseAddress = bytes.baseAddress else { return -1 }
            return pk_verifier_verify(
                verifier,
                baseAddress.assumingMemoryBound(to: UInt8.self),
                bytes.count,
                &errorPtr
            )
        }
        
        guard result == 0 else {
            let message = extractAndFreeError(errorPtr)
            throw ProveKitError.fromFFI(code: result, message: message)
        }
    }
    
    static func freeVerifier(_ handle: OpaquePointer) {
        pk_verifier_free(handle)
    }
    
    // MARK: - Proof Operations
    
    static func getPublicInputs(from proofData: Data) throws -> [[String: Any]] {
        try ensureInitialized()
        
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        var errorPtr: UnsafeMutablePointer<CChar>? = nil
        
        let result = proofData.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int32 in
            guard let baseAddress = bytes.baseAddress else { return -1 }
            return pk_proof_get_public_inputs(
                baseAddress.assumingMemoryBound(to: UInt8.self),
                bytes.count,
                &jsonPtr,
                &errorPtr
            )
        }
        
        guard result == 0, let json = jsonPtr else {
            let message = extractAndFreeError(errorPtr)
            throw ProveKitError.fromFFI(code: result, message: message)
        }
        
        defer { pk_free_string(json) }
        
        let jsonString = String(cString: json)
        guard let data = jsonString.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw ProveKitError.deserializationFailed("Failed to parse public inputs JSON")
        }
        
        return parsed
    }
    
    // MARK: - Helpers
    
    private static func extractAndFreeError(_ errorPtr: UnsafeMutablePointer<CChar>?) -> String? {
        guard let ptr = errorPtr else { return nil }
        let message = String(cString: ptr)
        pk_free_string(ptr)
        return message
    }
}
