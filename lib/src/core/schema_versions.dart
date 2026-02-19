// Machine-readable outputs change cautiously, and named schema constants make compatibility changes visible in review.

/// Machine-readable contract versions, independent of the tool release.
///
/// Increment a schema only for incompatible structural or semantic changes to
/// that specific persisted or emitted format.
const int reportSchemaVersion = 3;

/// Persistent analysis-cache envelope schema.
const int cacheSchemaVersion = 1;

/// Reserved schema for the versioned run manifest.
const int runManifestSchemaVersion = 1;
