import Foundation

public final class Verifier {
    
    private var handle: OpaquePointer?
    
    public private(set) var isConsumed: Bool = false
    
    public init(pkvData: Data) throws {
        self.handle = try FFIBridge.loadVerifier(from: pkvData)
    }
    
    public init(pkvPath: String) throws {
        self.handle = try FFIBridge.loadVerifier(from: pkvPath)
    }
    
    public convenience init(pkvURL: URL) throws {
        let data = try Data(contentsOf: pkvURL)
        try self.init(pkvData: data)
    }
    
    deinit {
        if let h = handle, !isConsumed {
            FFIBridge.freeVerifier(h)
        }
    }
    
    public func verify(_ proof: Proof) throws {
        guard !isConsumed else {
            throw ProveKitError.verifierConsumed
        }
        
        guard let h = handle else {
            throw ProveKitError.invalidInput("Verifier handle is invalid")
        }
        
        try FFIBridge.verify(verifier: h, proof: proof.serializedData)
        isConsumed = true
    }
}
