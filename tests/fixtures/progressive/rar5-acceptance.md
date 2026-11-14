# RAR5 article-loss acceptance

`tests/common/rar5_acceptance.rs` is an original first-party test-only wire writer. It uses the existing tiny RAR5 framing recipe and public crypto/checksum primitives. Generated archives and deterministic plaintext are not independent native-writer gold. No private fixture is redistributed.

The large workload is exactly 500,000,000 plaintext bytes, ten volumes and 700,000-byte physical articles including every final partial article. Plain parts carry 50,000,000 bytes each. The encrypted member uses one continuous CBC chain across nonaligned parts and separately encrypted headers. Its first two payload lengths are derived from the actual header size so article counts are 73,71,72,72,72,72,72,72,72,72. Both cases assert exactly 720 physical articles and exactly 72 lost articles. All framing-intersecting articles remain readable. An adjacent loss pair is mandatory; encrypted loss also crosses a nonaligned physical part through CBC taint. A separate 79-byte guard proves padding clipping because the large plaintext is block aligned.

`manifest.txt` version `task7-rar5-v1` records size/article/encryption/whole CRC/BLAKE; each part's global packed start, packed length, physical payload offset, physical size and whole-volume BLAKE; actual framing extents; every eligible/protected article; selected physical loss ranges; and the independently derived coalesced inner holes. Expected holes come from writer-recorded physical offsets and CBC own-plus-following-block taint, before engine entry. The offset-addressable SplitMix64 plaintext recipe, fixed test salt/IV and deterministic article ordering make fixtures reproducible. Keys/passwords are not included in result evidence.

The real public session receives an Opaque file-backed provider, one volume at a time with Wait and article NotYet transitions. Its original metadata/descriptors are forwarded truthfully; no publication authority is fabricated. Patches use the original Artifact capability in calls <=700,000 bytes. Whole-inner/part checks, all-byte gold comparison, strict ten-volume replacement evidence and public-readback export are required. Extraction plus strict replay have an exact finite KDF allowance; original physical reads must cover each byte/hole once across waits. Partial sparse snapshots, recovered output, physical read traces, manifests and results remain in the persistent private fixture directory. Both large sets share one gold inode through a hard link; the bounded writer validates the shared gold against the offset recipe rather than copying it.

Default tests run only scaled datasets <=1 MiB. The three ignored large entrypoints are not passed by the default suite. After a separately recorded resource lease, first compile the release test with the repository's release profile, then use its actual executable path (not Cargo) for preparation and measurements:

```sh
export ZIPFAST_TASK7_FIXTURES=/absolute/fresh/private/directory
export ZIPFAST_TASK7_LARGE_LEASE=granted
"$TEST_BINARY" --ignored --exact prepare_large_fixtures --nocapture --test-threads=1
# Independently hash/freeze all fixture bytes before the following engine calls.
/usr/bin/time -l "$TEST_BINARY" --ignored --exact plain_large_acceptance --nocapture --test-threads=1
/usr/bin/time -l "$TEST_BINARY" --ignored --exact encrypted_large_acceptance --nocapture --test-threads=1
```

Fixture generation/build and independent file hashing are outside timed children. Child time includes extraction, partial snapshot, bounded patching, complete verification and caller gold-readback/output export. OS peak process RSS includes Rust/native/runtime memory; available Mac block-I/O counters do not establish physical device traffic. These are correctness qualifications and establish no comparative throughput claim. Actual source/toolchain/environment/argv/executable/fixture hashes, raw counters and results must accompany a completion claim. RAR4, mapping/probing/seeking, 7z and caller adoption remain separate request gates.
