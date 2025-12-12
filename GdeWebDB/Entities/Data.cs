using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebDB.Entities
{
    public class User
    {
        public int USERID { get; set; }              // PK
        public Guid GUID { get; set; }
        public string PASSWORD { get; set; } = "";
        public string FIRSTNAME { get; set; } = "";
        public string LASTNAME { get; set; } = "";
        public string? EMAIL { get; set; }
        public bool ACTIVE { get; set; }
        public string USERDATAJSON { get; set; } = "";
        public DateTime MODIFICATIONDATE { get; set; }

        public string? PROFILEIMAGEURL { get; set; }


        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
        public ICollection<AuthToken> Tokens { get; set; } = new List<AuthToken>();
    }
}

// Entities/Role.cs
namespace GdeWebDB.Entities
{
    public class Role
    {
        public int ROLEID { get; set; }              // PK
        public string ROLENAME { get; set; } = "";
        public bool VALID { get; set; }
        public int MODIFIER { get; set; }
        public DateTime MODIFICATIONDATE { get; set; }

        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    }
}

// Entities/UserRole.cs
namespace GdeWebDB.Entities
{
    public class UserRole
    {
        public int USERROLES { get; set; }           // PK
        public int USERID { get; set; }
        public int ROLEID { get; set; } 
        public int CREATOR { get; set; }
        public DateTime CREATINGDATE { get; set; }

        public User User { get; set; } = default!;
        public Role Role { get; set; } = default!;
    }
}

// Entities/AuthToken.cs
namespace GdeWebDB.Entities
{
    public class AuthToken
    {
        public int TOKENID { get; set; }             // PK
        public int USERID { get; set; }
        public string TOKEN { get; set; } = "";
        public DateTime EXPIRATIONDATE { get; set; }

        public User User { get; set; } = default!;
    }
}

namespace GdeWebDB.Entities
{
    public class Course
    {
        public int COURSEID { get; set; }           // PK

        public string COURSETITLE { get; set; } = "";
        public string COURSEDESCRIPTION { get; set; } = "";

        public string COURSEFILE { get; set; } = "";
        public string COURSEFILETEXT { get; set; } = "";

        public string COURSEMEDIA { get; set; } = "";
        public string COURSEMEDIATEXT { get; set; } = "";
        public int COURSEMEDIADURATION { get; set; } = 0;

        public string COURSESUMMARYKEYWORDS { get; set; } = "";

        public string COURSEAIREQUESTJSON { get; set; } = "";

        public string COURSEAIRESPONSEJSON { get; set; } = "";

        public string COURSEDB { get; set; } = "";

        public DateTime MODIFICATIONDATE { get; set; }
    }
}

namespace GdeWebDB.Entities
{
    public class Quiz
    {
        public int QUIZID { get; set; }              // PK
        public int COURSEID { get; set; } = 0;

        public string QUIZQUESTION { get; set; } = "";
        public string QUIZANSWER1 { get; set; } = "";
        public string QUIZANSWER2 { get; set; } = "";
        public string QUIZANSWER3 { get; set; } = "";
        public string QUIZANSWER4 { get; set; } = "";
        public string QUIZSUCCESS { get; set; } = "";

        public DateTime MODIFICATIONDATE { get; set; }
    }
}