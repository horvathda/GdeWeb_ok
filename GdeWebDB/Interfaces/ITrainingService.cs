using GdeWebModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GdeWebDB.Interfaces
{
    public interface ITrainingService
    {
        // Course
        Task<CourseModel> GetCourse(CourseModel p);
        Task<CourseListModel> GetCourseList();
        Task<CourseListModel> GetCourseGeneratingList();
        Task<ResultModel> AddCourse(CourseModel p);
        Task<ResultModel> ModifyCourse(CourseModel p);
        Task<ResultModel> DeleteCourse(CourseModel p);

        // Quiz
        Task<QuizListModel> GetQuizList();
        Task<QuizListModel> GetCourseQuizzes(CourseModel p);
        Task<ResultModel> AddQuiz(QuizModel p);
        Task<ResultModel> ModifyQuiz(QuizModel p);
        Task<ResultModel> RemoveCourseQuizzes(CourseModel p);
        Task<ResultModel> RemoveQuiz(QuizModel p);
    }
}
