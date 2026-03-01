-- Minimal empty schema for VoucherSwap local environment (no legacy data)
-- Safe to run multiple times; uses IF NOT EXISTS guards.

/* Users */
IF OBJECT_ID('dbo.Users', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.Users (
    Id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    UserName NVARCHAR(256) NULL,
    NormalizedUserName NVARCHAR(256) NULL,
    Email NVARCHAR(256) NULL,
    NormalizedEmail NVARCHAR(256) NULL,
    EmailConfirmed BIT NOT NULL DEFAULT 0,
    PasswordHash NVARCHAR(MAX) NULL,
    SecurityStamp UNIQUEIDENTIFIER NULL,
    ConcurrencyStamp UNIQUEIDENTIFIER NULL,
    PhoneNumber NVARCHAR(50) NULL,
    PhoneNumberConfirmed BIT NOT NULL DEFAULT 0,
    TwoFactorEnabled BIT NOT NULL DEFAULT 0,
    LockoutEnd DATETIMEOFFSET NULL,
    LockoutEnabled BIT NOT NULL DEFAULT 0,
    AccessFailedCount INT NOT NULL DEFAULT 0,
    Fullname NVARCHAR(256) NULL,
    Status INT NOT NULL DEFAULT 1,
    ConsumptionBalance DECIMAL(18, 2) NOT NULL DEFAULT 0,
    AffiliateBalance DECIMAL(18, 2) NOT NULL DEFAULT 0,
    AccumulateBalance DECIMAL(18, 2) NOT NULL DEFAULT 0,
    SavingBalance DECIMAL(18, 2) NOT NULL DEFAULT 0,
    BusinessBalance DECIMAL(18, 2) NOT NULL DEFAULT 0,
    InvestBalance DECIMAL(18, 2) NOT NULL DEFAULT 0,
    CreatedOn DATETIME NULL,
    ModifiedOn DATETIME NULL
  );
END

/* Roles */
IF OBJECT_ID('dbo.Roles', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.Roles (
    Id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    Name NVARCHAR(256) NOT NULL,
    NormalizedName NVARCHAR(256) NULL
  );
END

/* UserRoles */
IF OBJECT_ID('dbo.UserRoles', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.UserRoles (
    UserId UNIQUEIDENTIFIER NOT NULL,
    RoleId UNIQUEIDENTIFIER NOT NULL,
    PRIMARY KEY (UserId, RoleId)
  );
END

/* RoleClaims */
IF OBJECT_ID('dbo.RoleClaims', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.RoleClaims (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    RoleId UNIQUEIDENTIFIER NOT NULL,
    ClaimType NVARCHAR(256) NULL,
    ClaimValue NVARCHAR(MAX) NULL
  );
END

/* Functions */
IF OBJECT_ID('dbo.Functions', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.Functions (
    Id NVARCHAR(128) NOT NULL PRIMARY KEY,
    Name NVARCHAR(256) NOT NULL,
    Url NVARCHAR(MAX) NULL,
    ParentId NVARCHAR(128) NULL,
    SortOrder INT NOT NULL DEFAULT 0,
    Status INT NOT NULL DEFAULT 1
  );
END

/* Permissions */
IF OBJECT_ID('dbo.Permissions', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.Permissions (
    RoleId UNIQUEIDENTIFIER NOT NULL,
    FunctionId NVARCHAR(128) NOT NULL,
    Feature NVARCHAR(1000) NOT NULL DEFAULT 'index',
    PRIMARY KEY (RoleId, FunctionId)
  );
END

/* UserTokens */
IF OBJECT_ID('dbo.UserTokens', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.UserTokens (
    UserId UNIQUEIDENTIFIER NOT NULL,
    LoginProvider NVARCHAR(450) NOT NULL,
    Name NVARCHAR(450) NOT NULL,
    Value NVARCHAR(MAX) NULL,
    PRIMARY KEY (UserId, LoginProvider, Name)
  );
END

/* Stores */
IF OBJECT_ID('dbo.Stores', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.Stores (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Name NVARCHAR(MAX) NOT NULL,
    Description NVARCHAR(MAX) NULL,
    Email NVARCHAR(512) NULL,
    PhoneNumber NVARCHAR(512) NULL,
    Address NVARCHAR(MAX) NOT NULL,
    Status INT NOT NULL DEFAULT 1,
    CategoryId INT NULL,
    AppUserId UNIQUEIDENTIFIER NULL,
    MapEmbed NVARCHAR(MAX) NULL,
    MapEmbedHtml NVARCHAR(MAX) NULL,
    MapIframe NVARCHAR(MAX) NULL,
    Latitude DECIMAL(18, 8) NULL,
    Longitude DECIMAL(18, 8) NULL,
    Url NVARCHAR(MAX) NULL,
    Logo NVARCHAR(MAX) NULL,
    Thumbnail NVARCHAR(MAX) NULL,
    CreatedOn DATETIME NULL CONSTRAINT DF_Stores_CreatedOn DEFAULT(GETDATE()),
    ModifiedOn DATETIME NULL CONSTRAINT DF_Stores_ModifiedOn DEFAULT(GETDATE())
  );
END

/* Project Catalogs */
IF OBJECT_ID('dbo.ProjectCatalogs', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.ProjectCatalogs (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Name NVARCHAR(256) NOT NULL
  );
END

/* Projects */
IF OBJECT_ID('dbo.Projects', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.Projects (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Name NVARCHAR(256) NOT NULL,
    Description NVARCHAR(MAX) NULL,
    Type INT NOT NULL DEFAULT 0,
    IsSystem BIT NOT NULL DEFAULT 0,
    Status INT NOT NULL DEFAULT 1,
    InvestBalance DECIMAL(18, 2) NOT NULL DEFAULT 0,
    ProjectCatalogId INT NULL,
    CreatedOn DATETIME NULL CONSTRAINT DF_Projects_CreatedOn DEFAULT(GETDATE()),
    ModifiedOn DATETIME NULL CONSTRAINT DF_Projects_ModifiedOn DEFAULT(GETDATE())
  );
END

/* InvestPackages */
IF OBJECT_ID('dbo.InvestPackages', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.InvestPackages (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Name NVARCHAR(256) NOT NULL,
    Price DECIMAL(18, 2) NOT NULL DEFAULT 0,
    Image NVARCHAR(MAX) NULL,
    OrderIndex INT NOT NULL DEFAULT 0,
    Status INT NOT NULL DEFAULT 1,
    CreatedOn DATETIME NULL CONSTRAINT DF_InvestPackages_CreatedOn DEFAULT(GETDATE())
  );
END

/* ProjectInvests */
IF OBJECT_ID('dbo.ProjectInvests', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.ProjectInvests (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    ProjectId INT NOT NULL,
    AppUserId UNIQUEIDENTIFIER NOT NULL,
    Amount DECIMAL(18, 2) NOT NULL DEFAULT 0,
    Remark NVARCHAR(512) NULL,
    Status INT NOT NULL DEFAULT 1,
    CreatedOn DATETIME NULL CONSTRAINT DF_ProjectInvests_CreatedOn DEFAULT(GETDATE()),
    ModifiedOn DATETIME NULL CONSTRAINT DF_ProjectInvests_ModifiedOn DEFAULT(GETDATE()),
    InvestPackageId INT NULL,
    TransactionHash NVARCHAR(128) NULL
  );
END

/* Wallet tables */
IF OBJECT_ID('dbo.WalletConsumptionTransactions', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.WalletConsumptionTransactions (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    TransactionHash NVARCHAR(128) NULL,
    AddressFrom NVARCHAR(MAX) NULL,
    AddressTo NVARCHAR(MAX) NULL,
    Fee DECIMAL(18, 2) NULL,
    FeeAmount DECIMAL(18, 2) NULL,
    AmountReceive DECIMAL(18, 2) NULL,
    Amount DECIMAL(18, 2) NULL,
    AppUserId UNIQUEIDENTIFIER NULL,
    Type INT NULL,
    Remark NVARCHAR(512) NULL,
    DateCreated DATETIME NULL CONSTRAINT DF_WalletConsumption_DateCreated DEFAULT(GETDATE())
  );
END

IF OBJECT_ID('dbo.WalletAffiliateTransactions', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.WalletAffiliateTransactions (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    TransactionHash NVARCHAR(128) NULL,
    AddressFrom NVARCHAR(MAX) NULL,
    AddressTo NVARCHAR(MAX) NULL,
    Fee DECIMAL(18, 2) NULL,
    FeeAmount DECIMAL(18, 2) NULL,
    AmountReceive DECIMAL(18, 2) NULL,
    Amount DECIMAL(18, 2) NULL,
    AppUserId UNIQUEIDENTIFIER NULL,
    Type INT NULL,
    Remark NVARCHAR(512) NULL,
    DateCreated DATETIME NULL CONSTRAINT DF_WalletAffiliate_DateCreated DEFAULT(GETDATE())
  );
END

IF OBJECT_ID('dbo.WalletAccumulateTransactions', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.WalletAccumulateTransactions (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    TransactionHash NVARCHAR(128) NULL,
    AddressFrom NVARCHAR(MAX) NULL,
    AddressTo NVARCHAR(MAX) NULL,
    Fee DECIMAL(18, 2) NULL,
    FeeAmount DECIMAL(18, 2) NULL,
    AmountReceive DECIMAL(18, 2) NULL,
    Amount DECIMAL(18, 2) NULL,
    AppUserId UNIQUEIDENTIFIER NULL,
    Type INT NULL,
    Remark NVARCHAR(512) NULL,
    DateCreated DATETIME NULL CONSTRAINT DF_WalletAccumulate_DateCreated DEFAULT(GETDATE())
  );
END

IF OBJECT_ID('dbo.WalletSavingTransactions', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.WalletSavingTransactions (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    TransactionHash NVARCHAR(128) NULL,
    AddressFrom NVARCHAR(MAX) NULL,
    AddressTo NVARCHAR(MAX) NULL,
    Fee DECIMAL(18, 2) NULL,
    FeeAmount DECIMAL(18, 2) NULL,
    AmountReceive DECIMAL(18, 2) NULL,
    Amount DECIMAL(18, 2) NULL,
    AppUserId UNIQUEIDENTIFIER NULL,
    Type INT NULL,
    Remark NVARCHAR(512) NULL,
    DateCreated DATETIME NULL CONSTRAINT DF_WalletSaving_DateCreated DEFAULT(GETDATE())
  );
END

IF OBJECT_ID('dbo.WalletBusinessTransactions', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.WalletBusinessTransactions (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    TransactionHash NVARCHAR(128) NULL,
    AddressFrom NVARCHAR(MAX) NULL,
    AddressTo NVARCHAR(MAX) NULL,
    Fee DECIMAL(18, 2) NULL,
    FeeAmount DECIMAL(18, 2) NULL,
    AmountReceive DECIMAL(18, 2) NULL,
    Amount DECIMAL(18, 2) NULL,
    AppUserId UNIQUEIDENTIFIER NULL,
    Type INT NULL,
    Remark NVARCHAR(512) NULL,
    DateCreated DATETIME NULL CONSTRAINT DF_WalletBusiness_DateCreated DEFAULT(GETDATE())
  );
END

IF OBJECT_ID('dbo.WalletInvestTransactions', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.WalletInvestTransactions (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    TransactionHash NVARCHAR(128) NULL,
    AddressFrom NVARCHAR(MAX) NULL,
    AddressTo NVARCHAR(MAX) NULL,
    Fee DECIMAL(18, 2) NULL,
    FeeAmount DECIMAL(18, 2) NULL,
    AmountReceive DECIMAL(18, 2) NULL,
    Amount DECIMAL(18, 2) NULL,
    AppUserId UNIQUEIDENTIFIER NULL,
    Type INT NULL,
    Remark NVARCHAR(512) NULL,
    DateCreated DATETIME NULL CONSTRAINT DF_WalletInvest_DateCreated DEFAULT(GETDATE())
  );
END

