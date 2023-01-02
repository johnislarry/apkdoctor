use apkdoctor;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn deserialize_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("deserialize-group");
    group.bench_function("deserialize", |b| {
        b.iter(|| {
            black_box(apkdoctor::deserialize(
                "./tests/assets/classes.dex".to_string(),
            ))
        })
    });
    group.finish();
}

criterion_group!(benches, deserialize_benchmark);
criterion_main!(benches);
