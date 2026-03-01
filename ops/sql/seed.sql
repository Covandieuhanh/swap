-- Seed minimal, clean data (no legacy records)

DECLARE @adminRole UNIQUEIDENTIFIER = '8497F93F-D389-494E-8A42-F58F3715B809'; -- protected in code
DECLARE @supportRole UNIQUEIDENTIFIER = '0E5C3F3D-7D3F-4E8A-9B09-5E21B6B1E111';
DECLARE @adminUser UNIQUEIDENTIFIER = '11111111-1111-1111-1111-111111111111';

/* Roles */
IF NOT EXISTS (SELECT 1 FROM dbo.Roles WHERE Id = @adminRole)
  INSERT INTO dbo.Roles (Id, Name, NormalizedName) VALUES (@adminRole, N'Admin', N'ADMIN');

IF NOT EXISTS (SELECT 1 FROM dbo.Roles WHERE Id = @supportRole)
  INSERT INTO dbo.Roles (Id, Name, NormalizedName) VALUES (@supportRole, N'Support', N'SUPPORT');

/* Functions (basic tree) */
IF NOT EXISTS (SELECT 1 FROM dbo.Functions WHERE Id = N'SYSTEM_MANAGEMENT')
  INSERT INTO dbo.Functions (Id, Name, Url, ParentId, SortOrder, Status)
  VALUES (N'SYSTEM_MANAGEMENT', N'System Management', N'/admin', NULL, 0, 1);

IF NOT EXISTS (SELECT 1 FROM dbo.Functions WHERE Id = N'ADMIN_DASHBOARD')
  INSERT INTO dbo.Functions (Id, Name, Url, ParentId, SortOrder, Status)
  VALUES (N'ADMIN_DASHBOARD', N'Admin Dashboard', N'/admin/dashboard', N'SYSTEM_MANAGEMENT', 1, 1);

/* Permissions */
IF NOT EXISTS (SELECT 1 FROM dbo.Permissions WHERE RoleId=@adminRole AND FunctionId=N'SYSTEM_MANAGEMENT')
  INSERT INTO dbo.Permissions (RoleId, FunctionId, Feature) VALUES (@adminRole, N'SYSTEM_MANAGEMENT', N'index');

IF NOT EXISTS (SELECT 1 FROM dbo.Permissions WHERE RoleId=@adminRole AND FunctionId=N'ADMIN_DASHBOARD')
  INSERT INTO dbo.Permissions (RoleId, FunctionId, Feature) VALUES (@adminRole, N'ADMIN_DASHBOARD', N'index');

/* Admin user (password: Admin123!) */
IF NOT EXISTS (SELECT 1 FROM dbo.Users WHERE Id = @adminUser)
BEGIN
  INSERT INTO dbo.Users (
    Id, Email, UserName, NormalizedEmail, NormalizedUserName, Fullname, PhoneNumber,
    PasswordHash, Status, EmailConfirmed, SecurityStamp, ConcurrencyStamp,
    ConsumptionBalance, AffiliateBalance, AccumulateBalance, SavingBalance, BusinessBalance, InvestBalance,
    CreatedOn, ModifiedOn
  )
  VALUES (
    @adminUser,
    N'admin@example.com',
    N'admin@example.com',
    N'ADMIN@EXAMPLE.COM',
    N'ADMIN@EXAMPLE.COM',
    N'Admin',
    NULL,
    N'AQAAAAEAACcQAAAAEFyW7stnqVvLUZjVJ1Xd5szA+G9ve5H7Btjr752aMySv7d3tbYz937UalRaVqSnJDA==', -- Admin123!
    1,
    1,
    NEWID(),
    NEWID(),
    0, 0, 0, 0, 0, 0,
    GETDATE(),
    GETDATE()
  );
END

/* UserRoles */
IF NOT EXISTS (SELECT 1 FROM dbo.UserRoles WHERE UserId=@adminUser AND RoleId=@adminRole)
  INSERT INTO dbo.UserRoles (UserId, RoleId) VALUES (@adminUser, @adminRole);

/* Sample catalog/project/package so front-end lists are not empty */
IF NOT EXISTS (SELECT 1 FROM dbo.ProjectCatalogs WHERE Name = N'Mặc định')
  INSERT INTO dbo.ProjectCatalogs (Name) VALUES (N'Mặc định');

DECLARE @catalogId INT = (SELECT TOP 1 Id FROM dbo.ProjectCatalogs ORDER BY Id);

IF NOT EXISTS (SELECT 1 FROM dbo.Projects WHERE Name = N'Dự án mẫu')
  INSERT INTO dbo.Projects (Name, Description, Type, IsSystem, Status, InvestBalance, ProjectCatalogId, CreatedOn, ModifiedOn)
  VALUES (N'Dự án mẫu', N'Dự án trống để thử giao diện', 0, 1, 1, 0, @catalogId, GETDATE(), GETDATE());

IF NOT EXISTS (SELECT 1 FROM dbo.InvestPackages WHERE Name = N'Gói mẫu 100')
  INSERT INTO dbo.InvestPackages (Name, Price, Image, OrderIndex, Status, CreatedOn)
  VALUES (N'Gói mẫu 100', 100, NULL, 1, 1, GETDATE());

