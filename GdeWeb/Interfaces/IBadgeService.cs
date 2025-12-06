using GdeWebModels;

namespace GdeWeb.Interfaces
{
    public interface IBadgeService
    {
        Task<List<UserBadgeModel>> GetBadges();

        Task<List<UserBadgeModel>> GetBadgeByUser(List<UserEventModel> UserBadges);

        Task<List<UserBadgeModel>> EvaluateAndPersistAsync(UserDataModel userData, IEnumerable<int> allCourseIds, DateTime? nowOverride = null);
    }
}