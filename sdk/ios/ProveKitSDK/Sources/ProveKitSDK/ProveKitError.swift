import Foundation

/// Errors that can occur when using ProveKit.
public enum ProveKitError: LocalizedError {
    /// Library not initialized. Call `ProveKit.initialize()` first.
    case notInitialized
    
    /// Invalid input provided (null pointer, empty data, etc.)
    case invalidInput(String)
    
    /// Failed to read prover key file or data
    case proverLoadFailed(String)
    
    /// Failed to read verifier key file or data
    case verifierLoadFailed(String)
    
    /// Proof generation failed
    case proveFailed(String)
    
    /// Proof verification failed (invalid proof)
    case verificationFailed(String)
    
    /// The verifier has already been consumed
    case verifierConsumed
    
    /// Failed to serialize data
    case serializationFailed(String)
    
    /// Failed to deserialize data
    case deserializationFailed(String)
    
    /// FFI call returned an unexpected error
    case ffiError(code: Int32, message: String?)
    
    /// An unknown error occurred
    case unknown(String)
    
    public var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "ProveKit is not initialized. Call ProveKit.initialize() first."
        case .invalidInput(let message):
            return "Invalid input: \(message)"
        case .proverLoadFailed(let message):
            return "Failed to load prover: \(message)"
        case .verifierLoadFailed(let message):
            return "Failed to load verifier: \(message)"
        case .proveFailed(let message):
            return "Proof generation failed: \(message)"
        case .verificationFailed(let message):
            return "Verification failed: \(message)"
        case .verifierConsumed:
            return "Verifier has already been used and cannot verify another proof."
        case .serializationFailed(let message):
            return "Serialization failed: \(message)"
        case .deserializationFailed(let message):
            return "Deserialization failed: \(message)"
        case .ffiError(let code, let message):
            return "FFI error (code \(code)): \(message ?? "unknown")"
        case .unknown(let message):
            return "Unknown error: \(message)"
        }
    }
}

// MARK: - FFI Error Code Mapping

extension ProveKitError {
    /// FFI error codes from PKError enum in Rust
    enum FFIErrorCode: Int32 {
        case success = 0
        case invalidInput = 1
        case schemeReadError = 2
        case witnessReadError = 3
        case proofError = 4
        case serializationError = 5
        case utf8Error = 6
        case fileWriteError = 7
        case verificationFailed = 8
        case verifierConsumed = 9
        case deserializationError = 10
    }
    
    /// Create a ProveKitError from an FFI error code and message.
    static func fromFFI(code: Int32, message: String?) -> ProveKitError {
        guard let ffiCode = FFIErrorCode(rawValue: code) else {
            return .ffiError(code: code, message: message)
        }
        
        let msg = message ?? "Unknown error"
        
        switch ffiCode {
        case .success:
            return .unknown("Success code should not create an error")
        case .invalidInput:
            return .invalidInput(msg)
        case .schemeReadError:
            return .proverLoadFailed(msg)
        case .witnessReadError:
            return .proveFailed(msg)
        case .proofError:
            return .proveFailed(msg)
        case .serializationError:
            return .serializationFailed(msg)
        case .utf8Error:
            return .deserializationFailed(msg)
        case .fileWriteError:
            return .serializationFailed(msg)
        case .verificationFailed:
            return .verificationFailed(msg)
        case .verifierConsumed:
            return .verifierConsumed
        case .deserializationError:
            return .deserializationFailed(msg)
        }
    }
}
