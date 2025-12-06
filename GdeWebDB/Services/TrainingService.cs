using GdeWebDB.Entities;
using GdeWebDB.Interfaces;
using GdeWebDB.Utilities;
using GdeWebModels;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.Reflection.Metadata;
using System.Transactions;

namespace GdeWebDB.Services
{
    public class TrainingService : ITrainingService
    {
        private readonly GdeDbContext _db;
        private readonly ILogService _log;

        public TrainingService(GdeDbContext db, ILogService logService)
        {
            _db = db;
            _log = logService;
        }


        // -------- COURSE --------


        public async Task<CourseModel> GetCourse(CourseModel p)
        {
            try
            {
                var c = await _db.A_COURSE
                    .AsNoTracking()
                    .Where(x => x.COURSEID == p.CourseId)
                    .Select(x => new CourseModel
                    {
                        CourseId = x.COURSEID,
                        CourseTitle = x.COURSETITLE,
                        CourseDescription = x.COURSEDESCRIPTION,
                        CourseFile = x.COURSEFILE,
                        CourseFileText = x.COURSEFILETEXT,
                        CourseMedia = x.COURSEMEDIA,
                        CourseMediaText = x.COURSEMEDIATEXT,
                        CourseMediaDuration = x.COURSEMEDIADURATION,
                        CourseSummaryKeywords = x.COURSESUMMARYKEYWORDS, 
                        CourseAiRequestJson = x.COURSEAIREQUESTJSON,  // setter tölti CourseAiRequest-t
                        CourseAiResponseJson = x.COURSEAIRESPONSEJSON, // setter tölti CourseAiResponse-t
                        CourseDB = x.COURSEDB,
                        ModificationDate = x.MODIFICATIONDATE,
                        Result = new ResultModel { Success = true }
                    })
                    .FirstOrDefaultAsync();

                return c ?? new CourseModel { Result = ResultTypes.NotFound };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "GetCourse");
                return new CourseModel { Result = ResultTypes.UnexpectedError };
            }
        }

        public async Task<CourseListModel> GetCourseList()
        {
            try
            {
                var list = await _db.A_COURSE
                    .AsNoTracking()
                    .OrderBy(x => x.COURSETITLE)
                    .ThenByDescending(x => x.MODIFICATIONDATE)
                    .Select(x => new CourseModel
                    {
                        CourseId = x.COURSEID,
                        CourseTitle = x.COURSETITLE,
                        CourseDescription = x.COURSEDESCRIPTION,
                        CourseFile = x.COURSEFILE,
                        CourseFileText = x.COURSEFILETEXT,
                        CourseMedia = x.COURSEMEDIA,
                        CourseMediaText = x.COURSEMEDIATEXT,
                        CourseMediaDuration = x.COURSEMEDIADURATION,
                        CourseSummaryKeywords = x.COURSESUMMARYKEYWORDS,
                        CourseAiRequestJson = x.COURSEAIREQUESTJSON,  // setter tölti CourseAiRequest-t
                        CourseAiResponseJson = x.COURSEAIRESPONSEJSON, // setter tölti CourseAiResponse-t
                        CourseDB = x.COURSEDB,
                        ModificationDate = x.MODIFICATIONDATE,
                    })
                    .ToListAsync();

                return new CourseListModel
                {
                    CourseList = list,
                    Result = new ResultModel { Success = true }
                };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "GetCourseList");
                return new CourseListModel { Result = ResultTypes.UnexpectedError };
            }
        }

        public async Task<CourseListModel> GetCourseGeneratingList()
        {
            try
            {
                var list = await _db.A_COURSE
                    .AsNoTracking()
                    .OrderByDescending(x => x.MODIFICATIONDATE)
                    .Where(x => (string.IsNullOrEmpty(x.COURSETITLE)) // csak azok, amelyeknél nincs még AI válasz
                                || string.IsNullOrEmpty(x.COURSEDB)) // vagy nincs vektor DB még
                    .OrderBy(x => x.COURSETITLE)
                    .ThenByDescending(x => x.MODIFICATIONDATE)
                    .Select(x => new CourseModel
                    {
                        CourseId = x.COURSEID,
                        CourseTitle = x.COURSETITLE,
                        CourseDescription = x.COURSEDESCRIPTION,
                        CourseFile = x.COURSEFILE,
                        CourseFileText = x.COURSEFILETEXT,
                        CourseMedia = x.COURSEMEDIA,
                        CourseMediaText = x.COURSEMEDIATEXT,
                        CourseMediaDuration = x.COURSEMEDIADURATION,
                        CourseSummaryKeywords = x.COURSESUMMARYKEYWORDS,
                        CourseAiRequestJson = x.COURSEAIREQUESTJSON,  // setter tölti CourseAiRequest-t
                        CourseAiResponseJson = x.COURSEAIRESPONSEJSON, // setter tölti CourseAiResponse-t
                        CourseDB = x.COURSEDB,
                        ModificationDate = x.MODIFICATIONDATE,
                    })
                    .ToListAsync();

                return new CourseListModel
                {
                    CourseList = list,
                    Result = new ResultModel { Success = true }
                };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "GetCourseList");
                return new CourseListModel { Result = ResultTypes.UnexpectedError };
            }
        }

        public async Task<ResultModel> AddCourse(CourseModel p)
        {
            try
            {
                var now = DateTime.UtcNow;

                var entity = new Course
                {
                    COURSETITLE = p.CourseTitle,
                    COURSEDESCRIPTION = p.CourseDescription,
                    COURSEFILE = p.CourseFile,
                    COURSEFILETEXT = p.CourseFileText,
                    COURSEMEDIA = p.CourseMedia,
                    COURSEMEDIATEXT = p.CourseMediaText,
                    COURSEMEDIADURATION = p.CourseMediaDuration,
                    COURSESUMMARYKEYWORDS = string.IsNullOrEmpty(p.CourseSummaryKeywords) ? string.Empty : p.CourseSummaryKeywords,
                    COURSEAIREQUESTJSON = string.IsNullOrEmpty(p.CourseAiRequest.Topic) ? "" : JsonConvert.SerializeObject(p.CourseAiRequest, Formatting.Indented),
                    COURSEAIRESPONSEJSON = string.IsNullOrEmpty(p.CourseAiResponse.title) ? "" : JsonConvert.SerializeObject(p.CourseAiResponse, Formatting.Indented),
                    COURSEDB = p.CourseDB,
                    MODIFICATIONDATE = now
                };

                _db.A_COURSE.Add(entity);
                await _db.SaveChangesAsync();

                // Visszaadhatjuk az új azonosítót az ErrorMessage-ben, ahogy a minta tette.
                return new ResultModel { Success = true, ErrorMessage = entity.COURSEID.ToString() };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "AddCourse");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> ModifyCourse(CourseModel p)
        {
            try
            {
                CourseAiRequestModel req = p.CourseAiRequest;
                var c = await _db.A_COURSE.FirstOrDefaultAsync(x => x.COURSEID == p.CourseId);
                if (c == null) return ResultTypes.NotFound;

                c.COURSETITLE = p.CourseTitle;
                c.COURSEDESCRIPTION = p.CourseDescription;
                c.COURSEFILE = p.CourseFile;
                c.COURSEFILETEXT = p.CourseFileText;
                c.COURSEMEDIA = p.CourseMedia;
                c.COURSEMEDIATEXT = p.CourseMediaText;
                c.COURSEMEDIADURATION = p.CourseMediaDuration;
                c.COURSESUMMARYKEYWORDS = string.IsNullOrEmpty(p.CourseSummaryKeywords) ? string.Empty : p.CourseSummaryKeywords;
                c.COURSEAIREQUESTJSON = string.IsNullOrEmpty(p.CourseAiRequest.Topic) ? "" : JsonConvert.SerializeObject(p.CourseAiRequest, Formatting.Indented);
                c.COURSEAIRESPONSEJSON = string.IsNullOrEmpty(p.CourseAiResponse.title) ? "" : JsonConvert.SerializeObject(p.CourseAiResponse, Formatting.Indented);
                c.COURSEDB = p.CourseDB;
                c.MODIFICATIONDATE = DateTime.UtcNow;

                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "ModifyCourse");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> DeleteCourse(CourseModel p)
        {
            try
            {
                using var tx = await _db.Database.BeginTransactionAsync();

                // Kapcsolt Quiz rekordok törlése (ha nincs ON DELETE CASCADE)
                var quizzes = _db.A_QUIZ.Where(q => q.COURSEID == p.CourseId);
                _db.A_QUIZ.RemoveRange(quizzes);
                await _db.SaveChangesAsync();

                var c = await _db.A_COURSE.FirstOrDefaultAsync(x => x.COURSEID == p.CourseId);
                if (c != null) _db.A_COURSE.Remove(c);

                await _db.SaveChangesAsync();
                await tx.CommitAsync();

                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "DeleteCourse");
                return ResultTypes.UnexpectedError;
            }
        }


        // -------- QUIZ --------


        public async Task<QuizListModel> GetQuizList()
        {
            try
            {
                var list = await _db.A_QUIZ
                    .AsNoTracking()
                    .OrderBy(x => x.COURSEID)
                    .ThenBy(x => x.QUIZID)
                    .Select(x => new QuizModel
                    {
                        QuizId = x.QUIZID,
                        CourseId = x.COURSEID,
                        QuizQuestion = x.QUIZQUESTION,
                        QuizAnswer1 = x.QUIZANSWER1,
                        QuizAnswer2 = x.QUIZANSWER2,
                        QuizAnswer3 = x.QUIZANSWER3,
                        QuizAnswer4 = x.QUIZANSWER4,
                        QuizSuccess = x.QUIZSUCCESS,
                        ModificationDate = x.MODIFICATIONDATE
                    })
                    .ToListAsync();

                return new QuizListModel
                {
                    QuizList = list,
                    Count = list.Count,
                    Result = new ResultModel { Success = true }
                };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "GetQuizList");
                return new QuizListModel { Result = ResultTypes.UnexpectedError };
            }
        }

        public async Task<QuizListModel> GetCourseQuizzes(CourseModel p)
        {
            try
            {
                var c = await _db.A_COURSE
                    .AsNoTracking()
                    .Where(x => x.COURSEID == p.CourseId)
                    .Select(x => new CourseModel
                    {
                        CourseId = x.COURSEID,
                        CourseTitle = x.COURSETITLE,
                        CourseDescription = x.COURSEDESCRIPTION,
                        CourseFile = x.COURSEFILE,
                        CourseFileText = x.COURSEFILETEXT,
                        CourseMedia = x.COURSEMEDIA,
                        CourseMediaText = x.COURSEMEDIATEXT,
                        CourseMediaDuration = x.COURSEMEDIADURATION,
                        CourseSummaryKeywords = x.COURSESUMMARYKEYWORDS,
                        CourseAiRequestJson = x.COURSEAIREQUESTJSON,  // setter tölti CourseAiRequest-t
                        CourseAiResponseJson = x.COURSEAIRESPONSEJSON, // setter tölti CourseAiResponse-t
                        CourseDB = x.COURSEDB,
                        ModificationDate = x.MODIFICATIONDATE,
                        Result = new ResultModel { Success = true }
                    })
                    .FirstOrDefaultAsync();

                List<QuizModel> list = new List<QuizModel>();
                foreach (var q in c.CourseAiResponse.quiz)
                {
                    // Mindig 4 válasz legyen
                    var answers = q.answers.ToList();
                    while (answers.Count < 4)
                        answers.Add(new QuizAnswer { text = "", correct = false });

                    // Helyes válasz szövege
                    var correctAnswer = answers.FirstOrDefault(a => a.correct)?.text ?? "";

                    var model = new QuizModel
                    {
                        CourseId = p.CourseId,
                        QuizQuestion = q.question,
                        QuizAnswer1 = answers[0].text,
                        QuizAnswer2 = answers[1].text,
                        QuizAnswer3 = answers[2].text,
                        QuizAnswer4 = answers[3].text,
                        QuizSuccess = correctAnswer,
                        ModificationDate = DateTime.Now
                    };

                    list.Add(model);
                }


                return new QuizListModel
                {
                    QuizList = list,
                    Count = list.Count,
                    Result = new ResultModel { Success = true }
                };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "GetCourseQuizzes");
                return new QuizListModel { Result = ResultTypes.UnexpectedError };
            }
        }

        public async Task<ResultModel> AddQuiz(QuizModel p)
        {
            try
            {
                var now = DateTime.UtcNow;

                var q = new Quiz
                {
                    COURSEID = p.CourseId,
                    QUIZQUESTION = p.QuizQuestion,
                    QUIZANSWER1 = p.QuizAnswer1,
                    QUIZANSWER2 = p.QuizAnswer2,
                    QUIZANSWER3 = p.QuizAnswer3,
                    QUIZANSWER4 = p.QuizAnswer4,
                    QUIZSUCCESS = p.QuizSuccess,
                    MODIFICATIONDATE = now
                };

                _db.A_QUIZ.Add(q);
                await _db.SaveChangesAsync();

                return new ResultModel { Success = true, ErrorMessage = q.QUIZID.ToString() };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "AddQuiz");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> ModifyQuiz(QuizModel p)
        {
            try
            {
                var q = await _db.A_QUIZ.FirstOrDefaultAsync(x => x.QUIZID == p.QuizId);
                if (q == null) return ResultTypes.NotFound;

                q.COURSEID = p.CourseId;
                q.QUIZQUESTION = p.QuizQuestion;
                q.QUIZANSWER1 = p.QuizAnswer1;
                q.QUIZANSWER2 = p.QuizAnswer2;
                q.QUIZANSWER3 = p.QuizAnswer3;
                q.QUIZANSWER4 = p.QuizAnswer4;
                q.QUIZSUCCESS = p.QuizSuccess;
                q.MODIFICATIONDATE = DateTime.UtcNow;

                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "ModifyQuiz");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> RemoveCourseQuizzes(CourseModel p)
        {
            try
            {
                var items = _db.A_QUIZ.Where(x => x.COURSEID == p.CourseId);
                _db.A_QUIZ.RemoveRange(items);
                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "RemoveCourseQuizzes");
                return ResultTypes.UnexpectedError;
            }
        }

        public async Task<ResultModel> RemoveQuiz(QuizModel p)
        {
            try
            {
                var q = await _db.A_QUIZ.FirstOrDefaultAsync(x => x.QUIZID == p.QuizId);
                if (q == null) return ResultTypes.NotFound;

                _db.A_QUIZ.Remove(q);
                await _db.SaveChangesAsync();
                return new ResultModel { Success = true };
            }
            catch (Exception ex)
            {
                await _log.WriteLogToFile(ex, "RemoveQuiz");
                return ResultTypes.UnexpectedError;
            }
        }
    }
}