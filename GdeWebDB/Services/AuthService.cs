using GdeWebDB.Entities;
using GdeWebDB.Interfaces;
using GdeWebDB.Utilities;
using Newtonsoft.Json;
using GdeWebModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory.Database;

namespace GdeWebDB.Services
{
    public class AuthService : IAuthService
    {
        private readonly GdeDbContext _db;

        private readonly ILogService _logService;

        public AuthService(GdeDbContext db, ILogService logService)
        {
            _db = db;
            _logService = logService;
        }

        public async Task<LoginResultModel> LoginWithGoogle(string email, string fullName, string picture)
        {
            try
            {
                string firstName = "";
                string lastName = "";

                if (!string.IsNullOrWhiteSpace(fullName))
                {
                    var parts = fullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    firstName = parts.FirstOrDefault() ?? "";
                    lastName = parts.Length > 1 ? string.Join(" ", parts.Skip(1)) : "";
                }

                var user = await _db.T_USER.FirstOrDefaultAsync(u => u.EMAIL == email);

                if (user == null)
                {
                    // 🆕 JSON alapú UserData
                    var userData = new UserDataModel();
                    if (!string.IsNullOrWhiteSpace(picture))
                    {
                        userData.ProfileImageUrl = picture;
                    }

                    user = new User
                    {
                        EMAIL = email,
                        FIRSTNAME = firstName,
                        LASTNAME = lastName,
                        ACTIVE = true,
                        GUID = Guid.NewGuid(),
                        USERDATAJSON = JsonConvert.SerializeObject(userData),
                        MODIFICATIONDATE = DateTime.UtcNow
                    };

                    _db.T_USER.Add(user);
                    await _db.SaveChangesAsync();

                    const int defaultRoleId = 2;

                    _db.K_USER_ROLES.Add(new UserRole
                    {
                        USERID = user.USERID,
                        ROLEID = defaultRoleId,
                        CREATOR = user.USERID,
                        CREATINGDATE = DateTime.UtcNow
                    });

                    await _db.SaveChangesAsync();
                }
                else
                {
                    user.FIRSTNAME = firstName;
                    user.LASTNAME = lastName;
                    user.ACTIVE = true;
                    user.MODIFICATIONDATE = DateTime.UtcNow;

                    // 🆕 meglévő JSON beolvasása, frissítése
                    var userData = string.IsNullOrWhiteSpace(user.USERDATAJSON)
                        ? new UserDataModel()
                        : JsonConvert.DeserializeObject<UserDataModel>(user.USERDATAJSON) ?? new UserDataModel();

                    if (!string.IsNullOrWhiteSpace(picture))
                    {
                        userData.ProfileImageUrl = picture;
                    }

                    user.USERDATAJSON = JsonConvert.SerializeObject(userData, Formatting.Indented);

                    await _db.SaveChangesAsync();

                    // ha még sincs szerepe, adjunk neki (defaultRoleId = 2)
                    bool hasAnyRole = await _db.K_USER_ROLES.AnyAsync(r => r.USERID == user.USERID);
                    if (!hasAnyRole)
                    {
                        const int defaultRoleId = 2;

                        _db.K_USER_ROLES.Add(new UserRole
                        {
                            USERID = user.USERID,
                            ROLEID = defaultRoleId,
                            CREATOR = user.USERID,
                            CREATINGDATE = DateTime.UtcNow
                        });

                        await _db.SaveChangesAsync();
                    }
                }

                // SZEREPEK BETÖLTÉSE
                var roles = await _db.K_USER_ROLES
                    .Where(ur => ur.USERID == user.USERID)
                    .Where(ur => ur.Role != null && !string.IsNullOrEmpty(ur.Role.ROLENAME))
                    .Select(ur => new LoginRoleModel
                    {
                        Id = ur.Role.ROLEID,
                        Name = ur.Role.ROLENAME
                    })
                    .Distinct()
                    .ToListAsync();

                return new LoginResultModel
                {
                    Id = user.USERID,
                    Guid = user.GUID,
                    Active = user.ACTIVE,
                    Roles = roles,
                    Result = new ResultModel
                    {
                        Success = true,
                        ErrorMessage = string.Empty
                    }
                };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "LoginWithGoogle hiba");
                return new LoginResultModel { Result = ResultTypes.UnexpectedError };
            }
        }



        public async Task<LoginResultModel> Login(LoginModel credential)
        {
            try
            {
                // 1) User lekérdezése email + hash alapján
                var user = await _db.T_USER
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u => u.EMAIL == credential.Email && u.PASSWORD == credential.Password);

                if (user == null)
                {
                    return new LoginResultModel
                    {
                        Result = new ResultModel
                        {
                            Success = false,
                            ErrorMessage = "Hibás e-mail vagy jelszó."
                        }
                    };
                }

                if (!user.ACTIVE)
                {
                    return new LoginResultModel
                    {
                        Result = new ResultModel
                        {
                            Success = false,
                            ErrorMessage = "A felhasználói fiók inaktív."
                        }
                    };
                }

                // 2) Szerepek (lehet több is)
                var roles = await _db.K_USER_ROLES
                    .Where(ur => ur.USERID == user.USERID)
                    .Where(ur => ur.Role != null && !string.IsNullOrEmpty(ur.Role.ROLENAME)) // árva/üres kizárása
                    .Select(ur => new LoginRoleModel
                    {
                        Id = ur.Role.ROLEID,
                        Name = ur.Role.ROLENAME
                    })
                    .Distinct() // ha lenne duplikált USERID–ROLEID
                    .ToListAsync();

                // 3) Összerakjuk a LoginResultModel-t
                return new LoginResultModel
                {
                    Id = user.USERID,
                    Guid = user.GUID,
                    Active = user.ACTIVE,
                    Roles = roles,
                    Result = new ResultModel
                    {
                        Success = true,
                        ErrorMessage = string.Empty
                    }
                };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "Login hiba");
                throw;
            }
        }

        // Az aktív mezőt nem vizsgálja -> Regisztrációs folyamatnál kell,
        // mielőtt a confirmation levél kimegy (UserController -> AddUser)
        public async Task<LoginResultModel> Auth(LoginModel credentials)
        {
            try
            {
                var user = await _db.T_USER
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u =>
                        u.EMAIL == credentials.Email &&
                        u.PASSWORD == credentials.Password);

                if (user == null)
                {
                    return new LoginResultModel
                    {
                        Result = new ResultModel
                        {
                            Success = false,
                            ErrorMessage = "Invalid username or password provided!"
                        }
                    };
                }

                var roles = await _db.K_USER_ROLES
                    .Where(ur => ur.USERID == user.USERID)
                    .Where(ur => ur.Role != null && !string.IsNullOrEmpty(ur.Role.ROLENAME))
                    .Select(ur => new LoginRoleModel
                    {
                        Id = ur.Role.ROLEID,
                        Name = ur.Role.ROLENAME
                    })
                    .Distinct()
                    .ToListAsync();

                return new LoginResultModel
                {
                    Id = user.USERID,
                    Guid = user.GUID,
                    Active = user.ACTIVE, // csak visszaadjuk, nem ellenőrizzük
                    Roles = roles,
                    Result = new ResultModel { Success = true }
                };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "Auth hiba");
                return new LoginResultModel { Result = ResultTypes.UnexpectedError };
            }
        }

        // Csak az email-t vizsgálja -> Elfelejtett jelszónál kell,
        // mielőtt a forgot password levél kimegy (UserController -> ForgotPassword)
        public async Task<LoginResultModel> Forgot(ForgotModel model)
        {
            try
            {
                var user = await _db.T_USER
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u => u.EMAIL == model.Email);

                if (user == null)
                {
                    return new LoginResultModel
                    {
                        Result = new ResultModel
                        {
                            Success = false,
                            ErrorMessage = "The provided email address does not exist!"
                        }
                    };
                }

                var roles = await _db.K_USER_ROLES
                    .Where(ur => ur.USERID == user.USERID)
                    .Where(ur => ur.Role != null && !string.IsNullOrEmpty(ur.Role.ROLENAME))
                    .Select(ur => new LoginRoleModel
                    {
                        Id = ur.Role.ROLEID,
                        Name = ur.Role.ROLENAME
                    })
                    .Distinct()
                    .ToListAsync();

                return new LoginResultModel
                {
                    Id = user.USERID,
                    Guid = user.GUID,
                    Active = user.ACTIVE,
                    Roles = roles,
                    Result = new ResultModel { Success = true }
                };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "Forgot hiba");
                return new LoginResultModel { Result = ResultTypes.UnexpectedError };
            }
        }

        public async Task<ResultModel> GetUserTokenExpirationDate(int userId, DateTime expirationDate)
        {
            // A régi logika EF-fel:
            // - ha van még nem lejárt token: a legkésőbbi lejáratút frissítjük, a többit töröljük
            // - ha nincs: töröljük az összes token-t és Result=false
            try
            {
                using var tx = await _db.Database.BeginTransactionAsync();

                var now = DateTime.UtcNow;

                var validTokens = await _db.T_AUTHENTICATION
                    .Where(t => t.USERID == userId && t.EXPIRATIONDATE > now)
                    .OrderByDescending(t => t.EXPIRATIONDATE)
                    .ToListAsync();

                if (validTokens.Count == 0)
                {
                    // nincs érvényes – mindent törlünk az adott userhez
                    var allUserTokens = _db.T_AUTHENTICATION.Where(t => t.USERID == userId);
                    _db.T_AUTHENTICATION.RemoveRange(allUserTokens);
                    await _db.SaveChangesAsync();
                    await tx.CommitAsync();

                    return new ResultModel
                    {
                        Success = false,
                        ErrorMessage = "The provided token does not exist or has expired!"
                    };
                }
                else
                {
                    var top = validTokens.First();

                    // friss lejárati dátum
                    top.EXPIRATIONDATE = expirationDate;
                    _db.T_AUTHENTICATION.Update(top);

                    // a többit töröljük
                    var others = validTokens.Skip(1);
                    _db.T_AUTHENTICATION.RemoveRange(others);

                    await _db.SaveChangesAsync();
                    await tx.CommitAsync();

                    return new ResultModel { Success = true };
                }
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "Login hiba");
                throw;
            }
        }

        public async Task<ResultModel> AddUserTokenExpirationDate(int userId, string token, DateTime expirationDate)
        {
            try
            {
                var entity = new AuthToken
                {
                    USERID = userId,
                    TOKEN = token,
                    EXPIRATIONDATE = expirationDate
                };

                _db.T_AUTHENTICATION.Add(entity);
                await _db.SaveChangesAsync();

                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "AddUserTokenExpirationDate hiba");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<LoginUserModel> GetUser(int userId)
        {
            try
            {
                // 1) User adatok
                var user = await _db.T_USER
                    .AsNoTracking()
                    .Where(u => u.USERID == userId)
                    .Select(u => new LoginUserModel
                    {
                        Id = u.USERID,
                        // Ha a LoginUserModel.Guid típusa string, akkor: Guid = u.GUID.ToString()
                        Guid = u.GUID,
                        FirstName = u.FIRSTNAME,
                        LastName = u.LASTNAME,
                        Email = u.EMAIL ?? String.Empty,
                        UserDataJson = u.USERDATAJSON,

                    })
                    .FirstOrDefaultAsync();

                if (user == null)
                    return new LoginUserModel { Result = ResultTypes.NotFound };

                // 2) Szerepkörök (INNER JOIN K_USER_ROLES → T_ROLE)
                user.Roles = await _db.K_USER_ROLES
                    .Where(ur => ur.USERID == userId)
                    .Where(ur => ur.Role != null && !string.IsNullOrEmpty(ur.Role.ROLENAME)) // árva/üres kizárása
                    .Select(ur => new LoginRoleModel
                    {
                        Id = ur.Role.ROLEID,
                        Name = ur.Role.ROLENAME
                    })
                    .Distinct() // ha lenne duplikált USERID–ROLEID
                    .ToListAsync();

                // 3) legfrissebb nem lejárt token beolvasása és beállítása
                var now = DateTime.UtcNow;
                var latestToken = await _db.T_AUTHENTICATION
                    .Where(t => t.USERID == userId && t.EXPIRATIONDATE > now)
                    .OrderByDescending(t => t.EXPIRATIONDATE)
                    .Select(t => t.TOKEN)
                    .FirstOrDefaultAsync();

                user.Token = latestToken ?? string.Empty;

                user.Result = new ResultModel { Success = true };
                return user;
            }
            catch (Exception ex)
            {
                // használd a saját log szolgáltatásod
                await _logService.WriteLogToFile(ex, "Login hiba");
                return new LoginUserModel { Result = ResultTypes.UnexpectedError }; // Megjegyzés
            }
        }

        public async Task<ResultModel> UserValidation(int userId, string userGuid)
        {
            try
            {
                // Ha a GUID az entitásban Guid típus, a userGuid-ot parse-oljuk:
                // (Ha string, az EF simán lefordítja string összehasonlításra.)
                bool isValid;
                try
                {
                    // Két lehetséges mappinghez kompatibilis megoldás:
                    isValid = await _db.T_USER.AnyAsync(u =>
                        u.USERID == userId &&
                        (u.GUID.ToString() == userGuid || u.GUID.ToString() == userGuid));
                }
                catch
                {
                    // Ha az előbbi nem fordítható SQL-re (ritka eset), egyszerűsítünk:
                    isValid = await _db.T_USER.AnyAsync(u => u.USERID == userId && u.GUID.ToString() == userGuid);
                }

                if (isValid)
                {
                    return new ResultModel { Success = true, ErrorMessage = "" };
                }
                else
                {
                    return new ResultModel { Success = false, ErrorMessage = "User is not valid!" };
                }
            }
            catch (Exception ex)
            {
                await _logService.WriteLogToFile(ex, "UserValidation hiba");
                return ResultTypes.UnexpectedError;
            }
        }
    }
}