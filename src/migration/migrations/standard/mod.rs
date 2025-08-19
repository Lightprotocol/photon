use sea_orm_migration::MigrationTrait;

pub mod m20220101_000001_init;
pub mod m20240623_000002_init;
pub mod m20240624_000003_init;
pub mod m20240807_000004_init;
pub mod m20240914_000005_init;
pub mod m20241008_000006_init;
pub mod m20250206_000007_init;
pub mod m20250314_000008_init;
pub mod m20250617_000152_fix_indexed_trees_unique_constraint;
pub mod m20250814_000009_fix_discriminator_precision;
pub mod m20250815_000010_fix_amounts_precision;

pub fn get_standard_migrations() -> Vec<Box<dyn MigrationTrait>> {
    vec![
        Box::new(m20220101_000001_init::Migration),
        Box::new(m20240623_000002_init::Migration),
        Box::new(m20240624_000003_init::Migration),
        Box::new(m20240807_000004_init::Migration),
        Box::new(m20240914_000005_init::Migration),
        Box::new(m20241008_000006_init::Migration),
        Box::new(m20250206_000007_init::Migration),
        Box::new(m20250314_000008_init::Migration),
        Box::new(m20250617_000152_fix_indexed_trees_unique_constraint::Migration),
        Box::new(m20250814_000009_fix_discriminator_precision::Migration),
        Box::new(m20250815_000010_fix_amounts_precision::Migration),
    ]
}
