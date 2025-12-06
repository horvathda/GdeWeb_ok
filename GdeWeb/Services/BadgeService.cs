
using GdeWeb.Interfaces;
using GdeWebModels;
using System.Reflection.Metadata.Ecma335;

namespace GdeWeb.Services
{
    public class BadgeService : IBadgeService
    {
        public async Task<List<UserBadgeModel>> GetBadges()
        {
            List<UserBadgeModel> Badges = new()
                {
                    new() {
                        Id = "first-flame",
                        Name = "Első Láng",
                        Description = "Első kurzus teljesítve.",
                        Icon = "🚀",
                        Points = 1,
                        Tier = BadgeTier.Bronze,
                        EarnedAt = DateTime.Now.AddDays(-10)
                    },
                    new() {
                        Id = "guardian-of-knowledge",
                        Name = "Tudásőrző",
                        Description = "3 napos megszakítás nélküli napi kvíz sorozat.",
                        Icon = "🔥",
                        Points = 0,
                        Tier = BadgeTier.Bronze,
                        EarnedAt = null
                    },

                    new() {
                        Id = "explorer",
                        Name = "Kutató",
                        Description = "Három kurzus teljesítve.",
                        Icon = "🌍",
                        Points = 3,
                        Tier = BadgeTier.Silver,
                        EarnedAt = DateTime.Now.AddDays(-7)
                    },
                    new() {
                        Id = "quiz-warrior",
                        Name = "Kvíz Harcos",
                        Description = "10 napos megszakítás nélküli napi kvíz sorozat.",
                        Icon = "🛡️",
                        Points = 0,
                        Tier = BadgeTier.Silver
                    },

                    new() {
                        Id = "master-of-science",
                        Name = "Tudomány Mestere",
                        Description = "Összes kurzus teljesítve.",
                        Icon = "🏆",
                        Points = 0,
                        Tier = BadgeTier.Gold
                    },
                    new() {
                        Id = "edu-star",
                        Name = "Edu AI Csillaga",
                        Description = "30 napos megszakítás nélküli napi kvíz sorozat.",
                        Icon = "🌟",
                        Points = 0,
                        Tier = BadgeTier.Gold
                    }
                };
        
            return Badges;
        }

        public async Task<List<UserBadgeModel>> GetBadgeByUser(List<UserEventModel> UserBadges)
        {
            var badges = await GetBadges();

            foreach (var badge in badges) {
                var userBadge = UserBadges.FirstOrDefault(b => b.BadgeId == badge.Id);

                if (userBadge != null)
                {
                    badge.Points = 1;
                    badge.EarnedAt = userBadge.ModificationDate;
                }
                else
                {
                    badge.Points = 0;
                    badge.EarnedAt = null;
                }
            }

            return badges;
        }

        /// <summary>
        /// Kiértékeli a jelvényeket a felhasználó jelenlegi UserData-ja alapján.
        /// Ha új jelvényt szerez, beírja a UserData.Badges listába (UserEventModel-ként).
        /// Visszaadja a FRISSEN megszerzett jelvények UserBadgeModel listáját.
        /// </summary>
        public async Task<List<UserBadgeModel>> EvaluateAndPersistAsync(UserDataModel userData, IEnumerable<int> allCourseIds, DateTime? nowOverride = null)
        {
            var now = nowOverride ?? DateTime.Now;
            var defs = await GetBadges();

            // ==== 1) Segédhalmazok ====
            // Megnézett kurzusok (int)
            var viewedCourseIds = new HashSet<int>(
                userData.Courses
                        .Where(c => c.CourseId > 0)
                        .Select(c => c.CourseId));

            // Sikeres kvízek (int) — logika: akkor "sikeres", ha van legalább 1 kérdés
            // és az eredmény >= kérdések száma (teljesen jó), vagy állíts be egy küszöböt (pl. 60%)
            const double PASS_RATIO = 0.60; // ha 100%-ot szeretnél, tedd 1.0-ra
            var passedQuizCourseIds = new HashSet<int>(
                userData.Quizzes
                        .Where(q => q.QuizQuestion > 0 &&
                                    (double)q.QuizResult / q.QuizQuestion >= PASS_RATIO)
                        .Select(q => q.CourseId));

            // Teljesített kurzusok = metszet
            var completedCourseIds = viewedCourseIds.Intersect(passedQuizCourseIds).ToList();
            int completedCourses = completedCourseIds.Count;

            // === 2) Napi kvíz streak számítás ===
            // Csak a Daily kvízek napjait nézzük (dátumokra normalizálva, idők nélkül)
            var dailyDates = userData.Quizzes
                             .Where(q => q.DailyQuiz)
                             .Select(q => q.ModificationDate.Date)
                             .Distinct()
                             .ToHashSet();

            int longestCurrentStreak = CalculateCurrentStreak(dailyDates, now.Date);

            // === 3) Jelvény-azonosítók a definícióból ===
            var firstFlameId = "first-flame";            // 1 kurzus teljesítve
            var explorerId = "explorer";                 // 3 kurzus teljesítve
            var masterId = "master-of-science";          // összes kurzus teljesítve
            var guardianId = "guardian-of-knowledge";    // 3 napos napi kvíz streak
            var quizWarriorId = "quiz-warrior";          // 10 napos napi kvíz streak
            var eduStarId = "edu-star";                  // 30 napos napi kvíz streak

            // Már megszerzett BadgeId-k
            var ownedBadgeIds = new HashSet<string>(
                userData.Badges
                        .Where(b => !string.IsNullOrWhiteSpace(b.BadgeId))
                        .Select(b => b.BadgeId!)
            );

            var newlyEarned = new List<UserBadgeModel>();

            // === 4) Kurzus-jelvények ===
            if (completedCourses >= 1 && !ownedBadgeIds.Contains(firstFlameId))
                AddBadge(userData, defs, firstFlameId, now, newlyEarned);

            if (completedCourses >= 3 && !ownedBadgeIds.Contains(explorerId))
                AddBadge(userData, defs, explorerId, now, newlyEarned);

            // "Összes kurzus teljesítve" - az allCourseIds alapján
            int totalCourses = allCourseIds?.Count() ?? 0;
            if (totalCourses > 0 && completedCourses >= totalCourses && !ownedBadgeIds.Contains(masterId))
                AddBadge(userData, defs, masterId, now, newlyEarned);

            // === 5) Napi kvíz streak-jelvények ===
            if (longestCurrentStreak >= 3 && !ownedBadgeIds.Contains(guardianId))
                AddBadge(userData, defs, guardianId, now, newlyEarned);

            if (longestCurrentStreak >= 10 && !ownedBadgeIds.Contains(quizWarriorId))
                AddBadge(userData, defs, quizWarriorId, now, newlyEarned);

            if (longestCurrentStreak >= 30 && !ownedBadgeIds.Contains(eduStarId))
                AddBadge(userData, defs, eduStarId, now, newlyEarned);

            return newlyEarned;
        }

        private static void AddBadge(
            UserDataModel userData,
            List<UserBadgeModel> defs,
            string badgeId,
            DateTime now,
            List<UserBadgeModel> newlyEarned)
        {
            // 1) Írd fel UserData.Badges-be (UserEventModel)
            userData.Badges.Add(new UserEventModel
            {
                BadgeId = badgeId,
                ModificationDate = now
            });

            // 2) Add vissza megjelenítéshez (UserBadgeModel a definícióból)
            var def = defs.FirstOrDefault(d => d.Id == badgeId);
            if (def != null)
            {
                // másolat, hogy ne írd felül a definíciót
                newlyEarned.Add(new UserBadgeModel
                {
                    Id = def.Id,
                    Name = def.Name,
                    Description = def.Description,
                    Icon = def.Icon,
                    Points = def.Points,
                    Tier = def.Tier,
                    EarnedAt = now
                });
            }
        }

        /// <summary>
        /// Visszaadja az aktuális (ma vagy tegnapig visszanyúló) folyamatos napi kvíz sorozat hosszát.
        /// Pl. ha ma nem volt kvíz, de tegnap és előtte volt folyamatosan, azt is számolja.
        /// </summary>
        private static int CalculateCurrentStreak(HashSet<DateTime> dailyDates, DateTime today)
        {
            if (dailyDates.Count == 0) return 0;

            // Streak indulási napja: ha ma nincs kvíz, de tegnap volt, akkor tegnapról indul
            DateTime cursor = dailyDates.Contains(today) ? today : today.AddDays(-1);
            if (!dailyDates.Contains(cursor)) return 0;

            int streak = 0;
            while (dailyDates.Contains(cursor))
            {
                streak++;
                cursor = cursor.AddDays(-1);
            }
            return streak;
        }
    }
}