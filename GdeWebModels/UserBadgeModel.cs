using Swashbuckle.AspNetCore.Annotations;

namespace GdeWebModels
{
    public enum BadgeTier
    {
        Bronze,
        Silver,
        Gold
    }

    [SwaggerSchema("Jelvény osztálya")]
    public class UserBadgeModel
    {
        [SwaggerSchema("Jelvény azonosítója")]
        public string Id { get; set; } = String.Empty;

        [SwaggerSchema("Jelvény neve")]
        public string Name { get; set; } = String.Empty;

        [SwaggerSchema("Jelvény leírása")]
        public string Description { get; set; } = String.Empty;

        /// <summary>
        /// Színes, nagy méretben megjelenő string (pl. emoji: 🚀, 🔬, 🌟)
        /// </summary>
        [SwaggerSchema("Jelvény ikonja")]
        public string Icon { get; set; } = "🌟";

        /// <summary>
        /// Hány pontot szerzett eddig a jelvényből (0 = még semmit)
        /// </summary>
        [SwaggerSchema("Jelvény pontja")]
        public int Points { get; set; }

        /// <summary>
        /// Szint: bronz, ezüst, arany
        /// </summary>
        [SwaggerSchema("Jelvény szintje")]
        public BadgeTier Tier { get; set; } = BadgeTier.Bronze;

        /// <summary>
        /// Mikor szerezte meg (ha még nem, akkor null)
        /// </summary>
        [SwaggerSchema("Jelvény megszerzésének dátuma")]
        public DateTime? EarnedAt { get; set; }
    }
}