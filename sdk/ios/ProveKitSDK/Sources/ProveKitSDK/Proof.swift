import Foundation

public struct Proof: Equatable {
    
    public let serializedData: Data
    
    public init(serializedData: Data) throws {
        guard !serializedData.isEmpty else {
            throw ProveKitError.invalidInput("Proof data is empty")
        }
        self.serializedData = serializedData
    }
    
    public func publicInputs() throws -> [[String: Any]] {
        try FFIBridge.getPublicInputs(from: serializedData)
    }
    
    public func serialized() throws -> Data {
        serializedData
    }
    
    public static func == (lhs: Proof, rhs: Proof) -> Bool {
        lhs.serializedData == rhs.serializedData
    }
}
