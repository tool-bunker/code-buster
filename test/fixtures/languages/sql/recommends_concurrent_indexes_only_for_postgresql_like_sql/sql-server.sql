IF OBJECT_ID('[dbo].[users]') IS NULL
BEGIN
  CREATE TABLE [dbo].[users] ([name] NVARCHAR(100));
END
GO
CREATE INDEX [idx_mssql] ON [dbo].[users] ([name]);
