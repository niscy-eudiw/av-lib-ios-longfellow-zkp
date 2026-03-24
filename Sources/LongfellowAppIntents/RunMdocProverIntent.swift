import AppIntents

/// Runs the mdoc prover flow.
public struct RunMdocProverIntent: AppIntent {
    public static var title: LocalizedStringResource {
        "Run mdoc prover"
    }

    public static var description: IntentDescription {
        IntentDescription("Starts the mdoc prover process.")
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, *)
    public static var supportedModes: IntentModes {
		.foreground
    }

    public init() {}

    public func perform() async throws -> some IntentResult {
        // TODO: Trigger your prover flow here.
		print("app intent running")
        return .result()
    }
}
