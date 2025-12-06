using GdeWebDB;                  // GdeDbContext
using GdeWebDB.Entities;
using GdeWebDB.Interfaces;
using GdeWebDB.Services;
using GdeWebDB.Utilities;
using GdeWebModels;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Data;
using System.Data.Common;

namespace GdeWebDB.Services
{
    public class UserService : IUserService
    {
        private readonly GdeDbContext _db;

        private ILogService _logService;

        private IMailService _mailService;

        public UserService(GdeDbContext db, ILogService logService, IMailService mailService)
        {
            _db = db;
            this._logService = logService;
            this._mailService = mailService;
        }



        // HITELESÍTÉS NÉLKÜL



        public async Task<UserModel> GetUser(int userId)
        {
            try
            {
                var u = await _db.T_USER
                    .AsNoTracking()
                    .Where(x => x.USERID == userId)
                    .Select(x => new UserModel
                    {
                        Id = x.USERID,
                        Guid = x.GUID,
                        FirstName = x.FIRSTNAME,
                        LastName = x.LASTNAME,
                        Email = x.EMAIL ?? string.Empty,
                        UserDataJson = x.USERDATAJSON,        // setter tölti UserData-t
                        Active = x.ACTIVE,
                        Modifier = 0                          // ha kell: tedd be, ha van ilyen oszlopod
                    })
                    .FirstOrDefaultAsync();

                if (u == null)
                    return new UserModel { Result = ResultTypes.NotFound };

                u.Roles = await _db.K_USER_ROLES
                    .Where(r => r.USERID == userId && r.Role != null && !string.IsNullOrEmpty(r.Role.ROLENAME))
                    .Select(r => new RoleModel
                    {
                        Id = r.Role.ROLEID,
                        Name = r.Role.ROLENAME,
                        UserId = userId
                    })
                    .Distinct()
                    .ToListAsync();

                u.Result = new ResultModel { Success = true };
                return u;
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "GetUser");
                return new UserModel { Result = ResultTypes.UnexpectedError };
            }
        }

        public async Task<RoleModel> GetRole(int roleId)
        {
            try
            {
                var r = await _db.T_ROLE
                    .AsNoTracking()
                    .Where(x => x.ROLEID == roleId)
                    .Select(x => new RoleModel { Id = x.ROLEID, Name = x.ROLENAME })
                    .FirstOrDefaultAsync();

                if (r == null) return new RoleModel { Result = ResultTypes.NotFound };
                r.Result = new ResultModel { Success = true };
                return r;
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "GetRole");
                return new RoleModel { Result = ResultTypes.UnexpectedError };
            }
        }



        // HITELESÍTÉSSEL



        public async Task<ResultModel> ModifyProfile(UserModel p)
        {
            try
            {
                var dupe = await _db.T_USER.AnyAsync(x => x.EMAIL == p.Email && x.USERID != p.Id);
                if (dupe)
                    return new ResultModel { Success = false, ErrorMessage = "Hiba! A megadott email cím már létezik!" };

                var u = await _db.T_USER.FirstOrDefaultAsync(x => x.USERID == p.Id);
                if (u == null) return ResultTypes.NotFound;

                if (!string.IsNullOrEmpty(p.Password)) u.PASSWORD = p.Password;
                u.FIRSTNAME = p.FirstName;
                u.LASTNAME = p.LastName;
                u.EMAIL = p.Email;
                u.USERDATAJSON = (p.UserData == null) ? "" : JsonConvert.SerializeObject(p.UserData, Formatting.Indented);
                u.MODIFICATIONDATE = DateTime.UtcNow;

                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "ModifyProfile");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ProfilePasswordModel> ModifyProfilePassword(ProfilePasswordModel p)
        {
            try
            {
                var u = await _db.T_USER.FirstOrDefaultAsync(x => x.USERID == p.Modifier);
                if (u == null) return new ProfilePasswordModel { Result = ResultTypes.NotFound };

                u.PASSWORD = p.ProfilePassword;
                u.MODIFICATIONDATE = DateTime.UtcNow;
                await _db.SaveChangesAsync();

                var tokens = _db.T_AUTHENTICATION.Where(t => t.USERID == p.Modifier);
                _db.T_AUTHENTICATION.RemoveRange(tokens);
                await _db.SaveChangesAsync();

                p.Result = new ResultModel { Success = true };
                return p;
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "ModifyProfilePassword");
                return new ProfilePasswordModel { Result = ResultTypes.UnexpectedError };
            }
        }



        public async Task<UserListModel> GetUserList()
        {
            try
            {
                var users = await _db.T_USER
                    .AsNoTracking()
                    .OrderBy(x => x.FIRSTNAME)
                    .Select(x => new UserModel
                    {
                        Id = x.USERID,
                        Guid = x.GUID,
                        FirstName = x.FIRSTNAME,
                        LastName = x.LASTNAME,
                        Email = x.EMAIL ?? string.Empty,
                        UserDataJson = x.USERDATAJSON,
                        Active = x.ACTIVE,
                        Modifier = 0
                    })
                    .ToListAsync();

                var allRoles = await _db.K_USER_ROLES
                    .AsNoTracking()
                    .Where(r => r.Role != null && !string.IsNullOrEmpty(r.Role.ROLENAME))
                    .Select(r => new RoleModel { Id = r.Role.ROLEID, Name = r.Role.ROLENAME, UserId = r.USERID })
                    .ToListAsync();

                foreach (var u in users)
                    u.Roles = allRoles.Where(rr => rr.UserId == u.Id).ToList();

                return new UserListModel { UserList = users, Result = new ResultModel { Success = true } };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "GetUserList");
                return new UserListModel { Result = ResultTypes.UnexpectedError };
            }
        }

        public async Task<ResultModel> AddUser(UserModel p)
        {
            try
            {
                var dupe = await _db.T_USER.AnyAsync(x => x.EMAIL == p.Email);
                if (dupe)
                    return new ResultModel { Success = false, ErrorMessage = "The provided email address already exists!" };

                var now = DateTime.UtcNow;

                var entity = new User
                {
                    GUID = Guid.NewGuid(),
                    PASSWORD = p.Password,
                    FIRSTNAME = p.FirstName,
                    LASTNAME = p.LastName,
                    EMAIL = p.Email,
                    USERDATAJSON = (p.UserData == null) ? "" : JsonConvert.SerializeObject(p.UserData, Formatting.Indented),
                    ACTIVE = p.Active,
                    MODIFICATIONDATE = now
                };

                _db.T_USER.Add(entity);
                await _db.SaveChangesAsync(); // itt lesz USERID

                var rolePairs = p.Roles.DistinctBy(d => new { d.Id, d.UserId }).ToList();
                foreach (var r in rolePairs)
                {
                    _db.K_USER_ROLES.Add(new UserRole
                    {
                        USERID = entity.USERID,
                        ROLEID = r.Id,
                        CREATOR = p.Modifier,
                        CREATINGDATE = now
                    });
                }
                await _db.SaveChangesAsync();

                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "AddUser");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> ModifyUser(UserModel p)
        {
            try
            {
                var dupe = await _db.T_USER.AnyAsync(x => x.EMAIL == p.Email && x.USERID != p.Id);
                if (dupe)
                    return new ResultModel { Success = false, ErrorMessage = "The provided email address already exists!" };

                var u = await _db.T_USER.FirstOrDefaultAsync(x => x.USERID == p.Id);
                if (u == null) return ResultTypes.NotFound;

                if (!string.IsNullOrEmpty(p.Password)) u.PASSWORD = p.Password;
                u.FIRSTNAME = p.FirstName;
                u.LASTNAME = p.LastName;
                u.EMAIL = p.Email;
                u.USERDATAJSON = (p.UserData == null) ? "" : JsonConvert.SerializeObject(p.UserData, Formatting.Indented);
                u.MODIFICATIONDATE = DateTime.UtcNow;

                // szerepek frissítése
                var current = _db.K_USER_ROLES.Where(r => r.USERID == p.Id);
                _db.K_USER_ROLES.RemoveRange(current);
                await _db.SaveChangesAsync();

                foreach (var r in p.Roles.DistinctBy(d => new { d.Id, d.UserId }))
                {
                    _db.K_USER_ROLES.Add(new UserRole
                    {
                        USERID = p.Id,
                        ROLEID = r.Id,
                        CREATOR = p.Modifier,
                        CREATINGDATE = DateTime.UtcNow
                    });
                }

                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "ModifyUser");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> DeleteUser(UserModel p)
        {
            try
            {
                using var tx = await _db.Database.BeginTransactionAsync();

                // A_* táblák – nyers SQL
                await _db.Database.ExecuteSqlRawAsync("DELETE FROM [dbo].[A_CHATHISTORY]  WHERE [USERID] = {0}", p.Id);
                await _db.Database.ExecuteSqlRawAsync("DELETE FROM [dbo].[A_FORUMHISTORY] WHERE [USERID] = {0}", p.Id);
                await _db.Database.ExecuteSqlRawAsync("DELETE FROM [dbo].[A_COST]         WHERE [USERID] = {0}", p.Id);

                // Auth + szerepek + user – EF
                _db.T_AUTHENTICATION.RemoveRange(_db.T_AUTHENTICATION.Where(t => t.USERID == p.Id));
                _db.K_USER_ROLES.RemoveRange(_db.K_USER_ROLES.Where(r => r.USERID == p.Id));

                var u = await _db.T_USER.FirstOrDefaultAsync(x => x.USERID == p.Id);
                if (u != null) _db.T_USER.Remove(u);

                await _db.SaveChangesAsync();
                await tx.CommitAsync();

                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "DeleteUser");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> SetUserState(UserModel p)
        {
            try
            {
                var u = await _db.T_USER.FirstOrDefaultAsync(x => x.USERID == p.Id);
                if (u == null) return ResultTypes.NotFound;

                u.ACTIVE = p.Active;
                u.MODIFICATIONDATE = DateTime.UtcNow;

                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "SetUserState");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> SetUserData(LoginUserModel p)
        {
            try
            {
                var u = await _db.T_USER.FirstOrDefaultAsync(x => x.USERID == p.Id);
                if (u == null) return ResultTypes.NotFound;

                u.USERDATAJSON = (p.UserData == null) ? "" : JsonConvert.SerializeObject(p.UserData, Formatting.Indented);
                u.MODIFICATIONDATE = DateTime.UtcNow;

                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "SetUserData");
                return ResultTypes.UnexpectedError;
            }
        }



        public async Task<RoleListModel> GetRoles()
        {
            try
            {
                var list = await _db.T_ROLE
                    .AsNoTracking()
                    .OrderBy(x => x.ROLEID)
                    .Select(x => new RoleModel { Id = x.ROLEID, Name = x.ROLENAME })
                    .ToListAsync();

                return new RoleListModel { RoleList = list, Result = new ResultModel { Success = true } };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "GetRoles");
                return new RoleListModel { Result = ResultTypes.UnexpectedError };
            }
        }

        public async Task<ResultModel> AddRole(RoleModel p)
        {
            try
            {
                var now = DateTime.UtcNow;
                _db.T_ROLE.Add(new Role
                {
                    ROLENAME = p.Name,
                    VALID = true,
                    MODIFIER = p.UserId,
                    MODIFICATIONDATE = now
                });
                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "AddRole");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> ModifyRole(RoleModel p)
        {
            try
            {
                var r = await _db.T_ROLE.FirstOrDefaultAsync(x => x.ROLEID == p.Id);
                if (r == null) return ResultTypes.NotFound;

                r.ROLENAME = p.Name;
                r.VALID = true;
                r.MODIFIER = p.UserId;
                r.MODIFICATIONDATE = DateTime.UtcNow;

                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "ModifyRole");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> DeleteRole(RoleModel p)
        {
            try
            {
                using var tx = await _db.Database.BeginTransactionAsync();

                await _db.Database.ExecuteSqlRawAsync("DELETE FROM [dbo].[K_ROLE_PERMISSIONS] WHERE [ROLEID] = {0}", p.Id);
                _db.K_USER_ROLES.RemoveRange(_db.K_USER_ROLES.Where(x => x.ROLEID == p.Id));

                var r = await _db.T_ROLE.FirstOrDefaultAsync(x => x.ROLEID == p.Id);
                if (r != null) _db.T_ROLE.Remove(r);

                await _db.SaveChangesAsync();
                await tx.CommitAsync();

                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "DeleteRole");
                return ResultTypes.UnexpectedError;
            }
        }
    }
}