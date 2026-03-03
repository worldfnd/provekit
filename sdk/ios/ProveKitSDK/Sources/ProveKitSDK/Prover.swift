import Foundation

public final class Prover {
    
    private let handle: OpaquePointer
    
    public init(pkpData: Data) throws {
        self.handle = try FFIBridge.loadProver(from: pkpData)
    }
    
    public init(pkpPath: String) throws {
        self.handle = try FFIBridge.loadProver(from: pkpPath)
    }
    
    public convenience init(pkpURL: URL) throws {
        let data = try Data(contentsOf: pkpURL)
        try self.init(pkpData: data)
    }
    
    deinit {
        FFIBridge.freeProver(handle)
    }
    
    public func prove(inputs: [String: Any]) throws -> Proof {
        let proofData = try FFIBridge.prove(prover: handle, inputs: inputs)
        return try Proof(serializedData: proofData)
    }
}
