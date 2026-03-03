import SwiftUI
import ProveKit

struct ContentView: View {
    @StateObject private var viewModel = ProofViewModel()
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                // Status Section
                GroupBox("Status") {
                    VStack(alignment: .leading, spacing: 8) {
                        StatusRow(label: "Prover", status: viewModel.proverStatus)
                        StatusRow(label: "Verifier", status: viewModel.verifierStatus)
                        StatusRow(label: "Proof", status: viewModel.proofStatus)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                
                // Input Section
                GroupBox("Circuit Inputs") {
                    VStack(spacing: 12) {
                        HStack {
                            Text("a:")
                            TextField("1", text: $viewModel.inputA)
                                .textFieldStyle(.roundedBorder)
                                .keyboardType(.numberPad)
                        }
                        HStack {
                            Text("b:")
                            TextField("2", text: $viewModel.inputB)
                                .textFieldStyle(.roundedBorder)
                                .keyboardType(.numberPad)
                        }
                    }
                }
                
                // Action Buttons
                VStack(spacing: 12) {
                    Button(action: viewModel.loadKeys) {
                        HStack {
                            Image(systemName: "key.fill")
                            Text("Load Keys")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(viewModel.isLoading)
                    
                    Button(action: viewModel.generateProof) {
                        HStack {
                            Image(systemName: "lock.shield.fill")
                            Text("Generate Proof")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
                    .disabled(!viewModel.canProve || viewModel.isLoading)
                    
                    Button(action: viewModel.verifyProof) {
                        HStack {
                            Image(systemName: "checkmark.shield.fill")
                            Text("Verify Proof")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.blue)
                    .disabled(!viewModel.canVerify || viewModel.isLoading)
                }
                
                // Result Section
                if let result = viewModel.result {
                    GroupBox("Result") {
                        HStack {
                            Image(systemName: result.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundColor(result.success ? .green : .red)
                            Text(result.message)
                                .font(.body)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                
                // Proof Details
                if let proofSize = viewModel.proofSize {
                    GroupBox("Proof Details") {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Size: \(proofSize) bytes")
                            if let timing = viewModel.proveTiming {
                                Text("Generation time: \(String(format: "%.2f", timing))s")
                            }
                        }
                        .font(.caption)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                
                Spacer()
                
                // Instructions
                Text("Place .pkp and .pkv files in the app bundle to use your own circuits")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding()
            .navigationTitle("ProveKit Demo")
            .overlay {
                if viewModel.isLoading {
                    ProgressView(viewModel.loadingMessage)
                        .padding()
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
            }
        }
    }
}

struct StatusRow: View {
    let label: String
    let status: LoadStatus
    
    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
            Spacer()
            HStack(spacing: 4) {
                Circle()
                    .fill(status.color)
                    .frame(width: 8, height: 8)
                Text(status.text)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

enum LoadStatus {
    case notLoaded
    case loading
    case loaded
    case error(String)
    
    var text: String {
        switch self {
        case .notLoaded: return "Not loaded"
        case .loading: return "Loading..."
        case .loaded: return "Ready"
        case .error(let msg): return msg
        }
    }
    
    var color: Color {
        switch self {
        case .notLoaded: return .gray
        case .loading: return .orange
        case .loaded: return .green
        case .error: return .red
        }
    }
}

struct ProofResult {
    let success: Bool
    let message: String
}

@MainActor
class ProofViewModel: ObservableObject {
    @Published var proverStatus: LoadStatus = .notLoaded
    @Published var verifierStatus: LoadStatus = .notLoaded
    @Published var proofStatus: LoadStatus = .notLoaded
    @Published var result: ProofResult?
    @Published var proofSize: Int?
    @Published var proveTiming: Double?
    @Published var isLoading = false
    @Published var loadingMessage = ""
    
    @Published var inputA = "1"
    @Published var inputB = "2"
    
    private var prover: Prover?
    private var verifier: Verifier?
    private var proof: Proof?
    
    var canProve: Bool {
        prover != nil && !inputA.isEmpty && !inputB.isEmpty
    }
    
    var canVerify: Bool {
        verifier != nil && proof != nil && !(verifier?.isConsumed ?? true)
    }
    
    func loadKeys() {
        Task {
            isLoading = true
            loadingMessage = "Loading prover key..."
            proverStatus = .loading
            
            do {
                // Try to load from bundle first
                if let pkpURL = Bundle.main.url(forResource: "prover", withExtension: "pkp") {
                    prover = try Prover(pkpURL: pkpURL)
                    proverStatus = .loaded
                } else {
                    // Use demo data (in a real app, download from server)
                    proverStatus = .error("No .pkp file in bundle")
                }
                
                loadingMessage = "Loading verifier key..."
                verifierStatus = .loading
                
                if let pkvURL = Bundle.main.url(forResource: "verifier", withExtension: "pkv") {
                    verifier = try Verifier(pkvURL: pkvURL)
                    verifierStatus = .loaded
                } else {
                    verifierStatus = .error("No .pkv file in bundle")
                }
                
                result = ProofResult(success: true, message: "Keys loaded successfully")
            } catch {
                result = ProofResult(success: false, message: error.localizedDescription)
                proverStatus = .error("Failed")
                verifierStatus = .error("Failed")
            }
            
            isLoading = false
        }
    }
    
    func generateProof() {
        guard let prover = prover else { return }
        
        Task {
            isLoading = true
            loadingMessage = "Generating proof..."
            proofStatus = .loading
            
            let startTime = Date()
            
            do {
                // Basic circuit: proves a + b = c where c = a + b
                let a = Int(inputA) ?? 1
                let b = Int(inputB) ?? 2
                let c = a + b
                let d = a * b + c // d = a*b + c
                
                proof = try prover.prove(inputs: [
                    "plains": [1, 2],
                    "a": a,
                    "b": b,
                    "c": c,
                    "d": d,
                    "x": 0,
                    "result": "0x0e90c132311e864e0c8bca37976f28579a2dd9436bbc11326e21ec7c00cea5b2"
                ])
                
                let elapsed = Date().timeIntervalSince(startTime)
                proveTiming = elapsed
                proofSize = proof?.serializedData.count
                proofStatus = .loaded
                result = ProofResult(success: true, message: "Proof generated in \(String(format: "%.2f", elapsed))s")
                
                // Reload verifier since it may have been consumed
                if verifier?.isConsumed == true {
                    if let pkvURL = Bundle.main.url(forResource: "verifier", withExtension: "pkv") {
                        verifier = try Verifier(pkvURL: pkvURL)
                        verifierStatus = .loaded
                    }
                }
            } catch {
                proofStatus = .error("Failed")
                result = ProofResult(success: false, message: error.localizedDescription)
            }
            
            isLoading = false
        }
    }
    
    func verifyProof() {
        guard let verifier = verifier, let proof = proof else { return }
        
        Task {
            isLoading = true
            loadingMessage = "Verifying proof..."
            
            do {
                try verifier.verify(proof)
                verifierStatus = .loaded
                result = ProofResult(success: true, message: "Proof verified successfully! ✓")
            } catch {
                result = ProofResult(success: false, message: "Verification failed: \(error.localizedDescription)")
            }
            
            // Verifier is consumed after verification
            if verifier.isConsumed {
                verifierStatus = .notLoaded
            }
            
            isLoading = false
        }
    }
}

#Preview {
    ContentView()
}
