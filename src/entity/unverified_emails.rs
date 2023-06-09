//! `SeaORM` Entity. Generated by sea-orm-codegen 0.11.3

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "unverified_emails")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub email: String,
    #[sea_orm(unique)]
    pub hash: String,
    #[sea_orm(unique)]
    pub salt: String,
    #[sea_orm(unique)]
    pub token: String,
    pub expires: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
