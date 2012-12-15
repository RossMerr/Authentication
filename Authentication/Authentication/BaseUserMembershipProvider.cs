using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Security;
using Authentication.Encryption;
using MvcContrib.Pagination;

namespace Authentication
{
    /// <summary>
    /// The redux membership provider.
    /// </summary>
    /// <typeparam name="TModel">
    /// </typeparam>
    /// <typeparam name="TId">
    /// </typeparam>
    public abstract class BaseUserMembershipProvider<TModel, TId> : MembershipProvider where TModel : IUser<TId>
    {

        /// <summary>
        /// The application name.
        /// </summary>
        private string applicationName;

        /// <summary>
        /// The enable password reset.
        /// </summary>
        private bool enablePasswordReset;

        /// <summary>
        /// The enable password retrieval.
        /// </summary>
        private bool enablePasswordRetrieval;

        /// <summary>
        /// The max invalid password attempts.
        /// </summary>
        private int maxInvalidPasswordAttempts = 3;

        /// <summary>
        /// The min required non alphanumeric characters.
        /// </summary>
        private int minRequiredNonAlphanumericCharacters;

        /// <summary>
        /// The min required password length.
        /// </summary>
        private int minRequiredPasswordLength = 8;

        /// <summary>
        /// The password attempt window.
        /// </summary>
        private int passwordAttemptWindow = 5;

        /// <summary>
        /// The password strength regular expression.
        /// </summary>
        private string passwordStrengthRegularExpression;

        /// <summary>
        /// The provider name.
        /// </summary>
        private string providerName = "UserMembershipProvider";

        /// <summary>
        /// The requires question and answer.
        /// </summary>
        private bool requiresQuestionAndAnswer;

        /// <summary>
        /// The requires unique email.
        /// </summary>
        private bool requiresUniqueEmail = true;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserMembershipProvider{TModel,TId}"/> class.
        /// </summary>
        public BaseUserMembershipProvider() : base()
        {
            
        }

        public override void Initialize(string name, System.Collections.Specialized.NameValueCollection config)
        {
            applicationName = config["applicationName"];

            bool.TryParse(config["enablePasswordReset"], out enablePasswordReset);
            bool.TryParse(config["enablePasswordRetrieval"], out enablePasswordRetrieval);
            int.TryParse(config["maxInvalidPasswordAttempts"], out maxInvalidPasswordAttempts);
            int.TryParse(config["minRequiredNonalphanumericCharacters"], out minRequiredNonAlphanumericCharacters);
            int.TryParse(config["minRequiredPasswordLength"], out minRequiredPasswordLength);
            int.TryParse(config["passwordAttemptWindow"], out passwordAttemptWindow);
            passwordStrengthRegularExpression = config["passwordStrengthRegularExpression"];
            bool.TryParse(config["requiresQuestionAndAnswer"], out requiresQuestionAndAnswer);
            bool.TryParse(config["requiresUniqueEmail"], out requiresUniqueEmail);

            base.Initialize(name, config);
        }


        /// <summary>
        /// Gets or sets ApplicationName.
        /// </summary>
        /// <exception cref="NullReferenceException">
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// </exception>
        public override string ApplicationName
        {
            get { return applicationName; }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new NullReferenceException("ApplicationName");
                }

                if (value.Length > 0x100)
                {
                    throw new ArgumentOutOfRangeException("Provider application name too long");
                }

                applicationName = value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether EnablePasswordReset.
        /// </summary>
        public override bool EnablePasswordReset
        {
            get { return enablePasswordReset; }
        }

        /// <summary>
        /// Gets a value indicating whether EnablePasswordRetrieval.
        /// </summary>
        public override bool EnablePasswordRetrieval
        {
            get { return enablePasswordRetrieval; }
        }

        /// <summary>
        /// Gets MaxInvalidPasswordAttempts.
        /// </summary>
        public override int MaxInvalidPasswordAttempts
        {
            get { return maxInvalidPasswordAttempts; }
        }

        /// <summary>
        /// Gets MinRequiredNonAlphanumericCharacters.
        /// </summary>
        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return minRequiredNonAlphanumericCharacters; }
        }

        /// <summary>
        /// Gets MinRequiredPasswordLength.
        /// </summary>
        public override int MinRequiredPasswordLength
        {
            get
            {
                return minRequiredPasswordLength;
            }
        }

        /// <summary>
        /// Gets PasswordAttemptWindow.
        /// </summary>
        public override int PasswordAttemptWindow
        {
            get { return passwordAttemptWindow; }
        }

        /// <summary>
        /// Gets PasswordFormat.
        /// </summary>
        public override MembershipPasswordFormat PasswordFormat
        {
            get { return MembershipPasswordFormat.Hashed; }
        }

        /// <summary>
        /// Gets PasswordStrengthRegularExpression.
        /// </summary>
        public override string PasswordStrengthRegularExpression
        {
            get { return passwordStrengthRegularExpression; }
        }

        /// <summary>
        /// Gets a value indicating whether RequiresQuestionAndAnswer.
        /// </summary>
        public override bool RequiresQuestionAndAnswer
        {
            get { return requiresQuestionAndAnswer; }
        }

        /// <summary>
        /// Gets a value indicating whether RequiresUniqueEmail.
        /// </summary>
        public override bool RequiresUniqueEmail
        {
            get { return requiresUniqueEmail; }
        }

        /// <summary>
        /// Gets or sets ProviderName.
        /// </summary>
        public string ProviderName
        {
            get
            {
                if (string.IsNullOrEmpty(Name))
                {
                    return providerName;
                }

                return Name;
            }

            set { providerName = value; }
        }

        /// <summary>
        /// The check password.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="salt">
        /// The salt.
        /// </param>
        /// <param name="encodePassword">
        /// The encode password.
        /// </param>
        /// <param name="newSalt">
        /// The new salt.
        /// </param>
        /// <returns>
        /// The check password.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// </exception>
        private bool CheckPassword(string username, string password, string salt, out string encodePassword,
                                   out string newSalt)
        {
            bool check = false;

            TModel user = GetUser(username);
            if (user != null)
            {
                if (salt == null)
                {
                    salt = user.Salt;
                }

                check = true;
            }

            if (salt == null)
            {
                salt = GenerateSalt();
            }

            newSalt = salt;

            if (password.Length < MinRequiredPasswordLength)
            {
                throw new ArgumentException("Password too short");
            }

            int num3 = 0;
            for (int i = 0; i < password.Length; i++)
            {
                if (!char.IsLetterOrDigit(password, i))
                {
                    num3++;
                }
            }

            if (num3 < MinRequiredNonAlphanumericCharacters)
            {
                throw new ArgumentException("Password need more non alpha numeric chars");
            }

            if (!string.IsNullOrEmpty(PasswordStrengthRegularExpression))
            {
                if ((PasswordStrengthRegularExpression.Length > 0) &&
                    !Regex.IsMatch(password, PasswordStrengthRegularExpression))
                {
                    throw new ArgumentException("Password does not match regular expression");
                }
            }

            encodePassword = EncodePassword(password, newSalt);
            if (encodePassword.Length > 0x80)
            {
                throw new ArgumentException("Membership password too long");
            }

            return check;
        }


        /// <summary>
        /// The get user.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <returns>
        /// </returns>
        public abstract TModel GetUser(string username);

        /// <summary>
        /// The get user by email.
        /// </summary>
        /// <param name="email">
        /// The email.
        /// </param>
        /// <returns>
        /// </returns>
        public abstract TModel GetUserByEmail(string email);

        /// <summary>
        /// The save.
        /// </summary>
        /// <param name="model">
        /// The model.
        /// </param>
        public abstract void Save(TModel model);

        /// <summary>
        /// The new model.
        /// </summary>
        /// <returns>
        /// </returns>
        public abstract TModel NewModel();

        /// <summary>
        /// The get by username.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <returns>
        /// </returns>
        public abstract TModel GetByUsername(string username);

        /// <summary>
        /// The delete.
        /// </summary>
        /// <param name="user">
        /// The user.
        /// </param>
        public abstract void Delete(TModel user);

        /// <summary>
        /// The get by email address.
        /// </summary>
        /// <param name="email">
        /// The email.
        /// </param>
        /// <param name="pageIndex">
        /// The page index.
        /// </param>
        /// <param name="pageSize">
        /// The page size.
        /// </param>
        /// <returns>
        /// </returns>
        public abstract IEnumerable<TModel> GetByEmailAddress(string email, int pageIndex, int pageSize);

        /// <summary>
        /// The get by username.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="pageIndex">
        /// The page index.
        /// </param>
        /// <param name="pageSize">
        /// The page size.
        /// </param>
        /// <returns>
        /// </returns>
        public abstract IEnumerable<TModel> GetByUsername(string username, int pageIndex, int pageSize);

        /// <summary>
        /// The get all.
        /// </summary>
        /// <returns>
        /// </returns>
        public abstract IEnumerable<TModel> GetAll();

        /// <summary>
        /// The get by id.
        /// </summary>
        /// <param name="id">
        /// The id.
        /// </param>
        /// <returns>
        /// </returns>
        public abstract TModel GetById(TId id);


        public abstract int GetNumberOfUsersOnline(DateTime period);

        /// <summary>
        /// The encode password.
        /// </summary>
        /// <param name="pass">
        /// The pass.
        /// </param>
        /// <param name="salt">
        /// The salt.
        /// </param>
        /// <returns>
        /// The encode password.
        /// </returns>
        private string EncodePassword(string pass, string salt)
        {
            return Hash.ComputeHash(pass, HashAlgorithm.SHA512, salt);
        }

        /// <summary>
        /// The change password.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="oldPassword">
        /// The old password.
        /// </param>
        /// <param name="newPassword">
        /// The new password.
        /// </param>
        /// <returns>
        /// The change password.
        /// </returns>
        /// <exception cref="Exception">
        /// </exception>
        /// <exception cref="ArgumentException">
        /// </exception>
        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            string encodePassword;
            string salt;

            if (!ValidateUser(username, oldPassword))
                return false;

            CheckPassword(username, newPassword, null, out encodePassword, out salt);


            var e = new ValidatePasswordEventArgs(username, newPassword, false);
            OnValidatingPassword(e);

            if (e.Cancel)
            {
                if (e.FailureInformation != null)
                {
                    throw e.FailureInformation;
                }

                throw new ArgumentException("Membership Custom Password Validation Failure");
            }

            try
            {
                TModel user = GetUser(username);
                user.ChangePassword(encodePassword, salt);
                Save(user);
            }
            catch
            {
                throw;
            }

            return true;
        }

        /// <summary>
        /// The change password question and answer.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="newPasswordQuestion">
        /// The new password question.
        /// </param>
        /// <param name="newPasswordAnswer">
        /// The new password answer.
        /// </param>
        /// <returns>
        /// The change password question and answer.
        /// </returns>
        public override bool ChangePasswordQuestionAndAnswer(string username, string password,
                                                             string newPasswordQuestion, string newPasswordAnswer)
        {
            string newPassword;
            string encodePasswordQuestionAnswer;
            string salt;
            CheckPassword(username, password, null, out newPassword, out salt);


            if (!string.IsNullOrEmpty(newPasswordAnswer))
            {
                encodePasswordQuestionAnswer = EncodePassword(newPasswordAnswer.ToLower(), salt);
            }
            else
            {
                encodePasswordQuestionAnswer = newPasswordAnswer.ToLower();
            }

            try
            {
                TModel user = GetUser(username);
                user.ChangePasswordQuestionAndAnswer(newPasswordQuestion, encodePasswordQuestionAnswer);
                Save(user);
            }
            catch
            {
                throw;
            }

            return true;
        }

        /// <summary>
        /// The generate salt.
        /// </summary>
        /// <returns>
        /// The generate salt.
        /// </returns>
        private string GenerateSalt()
        {
            return Hash.Salt();
        }

        /// <summary>
        /// The create user.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="email">
        /// The email.
        /// </param>
        /// <param name="passwordQuestion">
        /// The password question.
        /// </param>
        /// <param name="passwordAnswer">
        /// The password answer.
        /// </param>
        /// <param name="isApproved">
        /// The is approved.
        /// </param>
        /// <param name="providerUserKey">
        /// The provider user key.
        /// </param>
        /// <param name="status">
        /// The status.
        /// </param>
        /// <returns>
        /// </returns>
        public override MembershipUser CreateUser(string username, string password, string email,
                                                  string passwordQuestion, string passwordAnswer, bool isApproved,
                                                  object providerUserKey, out MembershipCreateStatus status)
        {
            MembershipUser user;
            status = MembershipCreateStatus.UserRejected;
            string encodePassword;
            string encodePasswordQuestionAnswer;

            if (!password.Validate(true, true, true, 80))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (password.Length < MinRequiredPasswordLength)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            int num3 = 0;
            for (int i = 0; i < password.Length; i++)
            {
                if (!char.IsLetterOrDigit(password, i))
                {
                    num3++;
                }
            }

            if (num3 < MinRequiredNonAlphanumericCharacters)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (!string.IsNullOrEmpty(PasswordStrengthRegularExpression))
            {
                if ((PasswordStrengthRegularExpression.Length > 0) &&
                    !Regex.IsMatch(password, PasswordStrengthRegularExpression))
                {
                    status = MembershipCreateStatus.InvalidPassword;
                    return null;
                }
            }

            string salt;
            CheckPassword(username, password, null, out encodePassword, out salt);

            if (!username.Validate(true, true, true, 100))
            {
                status = MembershipCreateStatus.InvalidUserName;
                return null;
            }

            if (passwordAnswer != null)
            {
                passwordAnswer = passwordAnswer.Trim();
            }

            if (!string.IsNullOrEmpty(passwordAnswer))
            {
                if (passwordAnswer.Length > 0x80)
                {
                    status = MembershipCreateStatus.InvalidAnswer;
                    return null;
                }

                encodePasswordQuestionAnswer = EncodePassword(passwordAnswer.ToLower(), salt);
            }
            else
            {
                encodePasswordQuestionAnswer = passwordAnswer;
            }

            if (!encodePasswordQuestionAnswer.Validate(RequiresQuestionAndAnswer, true, false, 80))
            {
                status = MembershipCreateStatus.InvalidAnswer;
                return null;
            }

            if (GetUser(username, false) != null)
            {
                status = MembershipCreateStatus.DuplicateUserName;
                return null;
            }

            if (!email.Validate(RequiresUniqueEmail, RequiresUniqueEmail, false,100))
            {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }

            if (GetUserByEmail(email) != null)
            {
                status = MembershipCreateStatus.DuplicateEmail;
                return null;
            }

            if (!passwordQuestion.Validate(RequiresQuestionAndAnswer, true, false,100))
            {
                status = MembershipCreateStatus.InvalidQuestion;
                return null;
            }

            if ((providerUserKey != null) && !(providerUserKey is Guid))
            {
                status = MembershipCreateStatus.InvalidProviderUserKey;
                return null;
            }

            var e = new ValidatePasswordEventArgs(username, password, true);

            OnValidatingPassword(e);

            if (e.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            try
            {
                var now = DateTime.UtcNow;
                var CMSuser = UserFactory.CreateUser(username, encodePassword, email, passwordQuestion, encodePasswordQuestionAnswer, isApproved, salt);

                Save(CMSuser);
                status = MembershipCreateStatus.Success;
                user = new MembershipUser(ProviderName, username, CMSuser.Id, email, passwordQuestion, null, isApproved,
                                          false, now, now, now, now, new DateTime(0x6da, 1, 1));
            }
            catch
            {
                throw;
            }

            return user;
        }


        /// <summary>
        /// The delete user.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="deleteAllRelatedData">
        /// The delete all related data.
        /// </param>
        /// <returns>
        /// The delete user.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// </exception>
        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            if (!username.Validate(true, true, true, 100))
            {
                throw new ArgumentException("Invalide username");
            }

            var user = GetByUsername(username);
            if (user != null)
            {
                Delete(user);
                return true;
            }

            return false;
        }


        /// <summary>
        /// The find users by email.
        /// </summary>
        /// <param name="emailToMatch">
        /// The email to match.
        /// </param>
        /// <param name="pageIndex">
        /// The page index.
        /// </param>
        /// <param name="pageSize">
        /// The page size.
        /// </param>
        /// <param name="totalRecords">
        /// The total records.
        /// </param>
        /// <returns>
        /// </returns>
        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize,
                                                                  out int totalRecords)
        {
            totalRecords = 0;
            var coll = new MembershipUserCollection();
            var users = GetByEmailAddress(emailToMatch, pageIndex, pageSize);
            if (users != null)
            {
                totalRecords = users.Count();
                if (users.Any())
                {                   
                   foreach (var user in users.AsPagination(pageIndex, pageSize))
                    {
                        coll.Add(new MembershipUser(ProviderName, user.Username, user.Id, user.Email, user.PasswordQuestion,
                                                    user.Comment, user.IsApproved, user.IsLockedOut, user.DateCreated,
                                                    user.LastLoginDate, user.LastActiveDate, user.LastPasswordChangedDate,
                                                    user.LastLockoutDate));
                    }
                }
            }

            return coll;
        }

        /// <summary>
        /// The find users by name.
        /// </summary>
        /// <param name="usernameToMatch">
        /// The username to match.
        /// </param>
        /// <param name="pageIndex">
        /// The page index.
        /// </param>
        /// <param name="pageSize">
        /// The page size.
        /// </param>
        /// <param name="totalRecords">
        /// The total records.
        /// </param>
        /// <returns>
        /// </returns>
        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize,
                                                                 out int totalRecords)
        {
            var coll = new MembershipUserCollection();

            var users = GetByUsername(usernameToMatch, pageIndex, pageSize);

            if (users.Any())
            {
                foreach (var user in users.AsPagination(pageIndex, pageSize))
                {
                    coll.Add(new MembershipUser(ProviderName, user.Username, user.Id, user.Email, user.PasswordQuestion,
                                                user.Comment, user.IsApproved, user.IsLockedOut, user.DateCreated,
                                                user.LastLoginDate, user.LastActiveDate, user.LastPasswordChangedDate,
                                                user.LastLockoutDate));
                }
            }

            totalRecords = users.Count();
            return coll;
        }

        /// <summary>
        /// The get all users.
        /// </summary>
        /// <param name="pageIndex">
        /// The page index.
        /// </param>
        /// <param name="pageSize">
        /// The page size.
        /// </param>
        /// <param name="totalRecords">
        /// The total records.
        /// </param>
        /// <returns>
        /// </returns>
        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            var coll = new MembershipUserCollection();
            var users = GetAll();
            if (users.Any())
            {
                foreach (TModel user in users.AsPagination(pageIndex, pageSize))
                {
                    coll.Add(new MembershipUser(ProviderName, user.Username, user.Id, user.Email, user.PasswordQuestion,
                                                user.Comment, user.IsApproved, user.IsLockedOut, user.DateCreated,
                                                user.LastLoginDate, user.LastActiveDate, user.LastPasswordChangedDate,
                                                user.LastLockoutDate));
                }
            }

            totalRecords = users.Count();
            return coll;
        }

        /// <summary>
        /// The get number of users online.
        /// </summary>
        /// <returns>
        /// The get number of users online.
        /// </returns>
        public override int GetNumberOfUsersOnline()
        {
            var activeDate = DateTime.UtcNow.AddMinutes(-System.Web.Security.Membership.UserIsOnlineTimeWindow);
            return GetNumberOfUsersOnline(activeDate);
        }

        /// <summary>
        /// The get password.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="answer">
        /// The answer.
        /// </param>
        /// <returns>
        /// The get password.
        /// </returns>
        /// <exception cref="NotSupportedException">
        /// </exception>
        public override string GetPassword(string username, string answer)
        {
            throw new NotSupportedException("Provider can not decode hashed password");
        }

        /// <summary>
        /// The get user.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="userIsOnline">
        /// The user is online.
        /// </param>
        /// <returns>
        /// </returns>
        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            if (!username.Validate(true, true, true,100)) return null;            

            var user = GetByUsername(username);
            if (user == null) return null;
            
            if (userIsOnline)
            {
                user.UserIsOnline();
            }

            return new MembershipUser(ProviderName, user.Username, user.Id, user.Email, user.PasswordQuestion,
                                      user.Comment, user.IsApproved, user.IsLockedOut, user.DateCreated,
                                      user.LastLoginDate, user.LastActiveDate, user.LastPasswordChangedDate,
                                      user.LastLockoutDate);
        }


        /// <summary>
        /// The get user.
        /// </summary>
        /// <param name="providerUserKey">
        /// The provider user key.
        /// </param>
        /// <param name="userIsOnline">
        /// The user is online.
        /// </param>
        /// <returns>
        /// </returns>
        /// <exception cref="ArgumentException">
        /// </exception>
        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            if (!(providerUserKey is TId)) throw new ArgumentException("Membership InvalidProviderUserKey");
            
            var userId = (TId)providerUserKey;

            var user = GetById(userId);
            
            if (user == null) return null;
            
            if (userIsOnline)
            {
                user.UserIsOnline();
            }

            return new MembershipUser(ProviderName, user.Username, user.Id, user.Email, user.PasswordQuestion,
                                      user.Comment, user.IsApproved, user.IsLockedOut, user.DateCreated,
                                      user.LastLoginDate, user.LastActiveDate, user.LastPasswordChangedDate,
                                      user.LastLockoutDate);
        }

        /// <summary>
        /// The get user name by email.
        /// </summary>
        /// <param name="email">
        /// The email.
        /// </param>
        /// <returns>
        /// The get user name by email.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// </exception>
        public override string GetUserNameByEmail(string email)
        {
            if (!email.Validate(RequiresUniqueEmail, RequiresUniqueEmail, false,100)) throw new ArgumentException("Invalid email");
            
            var user = GetUserByEmail(email);

            return user != null ? user.Username : string.Empty;
        }

        /// <summary>
        /// The get salt.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <returns>
        /// The get salt.
        /// </returns>
        private string GetSalt(string username)
        {
            if (string.IsNullOrEmpty(username)) return null;
            
            var user = GetByUsername(username);
            return user != null ? user.Salt : null;
        }

        /// <summary>
        /// The get by username and question answer.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="encodePasswordQuestionAnswer">
        /// The encode password question answer.
        /// </param>
        /// <returns>
        /// </returns>
        public abstract IEnumerable<TModel> GetByUsernameAndQuestionAnswer(string username,
                                                                           string encodePasswordQuestionAnswer);


        public static string CreateRandomPassword(int passwordLength)
        {
            const string allowedChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789";
            var randNum = new Random();
            var chars = new char[passwordLength];

            for (var i = 0; i < passwordLength; i++)
            {
                chars[i] = allowedChars[(int)((allowedChars.Length) * randNum.NextDouble())];
            }

            return new string(chars);
        }
        /// <summary>
        /// The reset password.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="answer">
        /// The answer.
        /// </param>
        /// <returns>
        /// The reset password.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// </exception>
        public override string ResetPassword(string username, string answer)
        {
            if (!username.Validate(true, true, true, 100)) throw new ArgumentException("Invalid username");
            
            var newPassword = CreateRandomPassword((MinRequiredPasswordLength < 0) ? 14 : MinRequiredPasswordLength);
            var salt = GetSalt(username);
            var encodeNewPassword = EncodePassword(newPassword, salt);
            string encodePasswordQuestionAnswer;

            if (string.IsNullOrEmpty(answer))
            {
                encodePasswordQuestionAnswer = answer;
            }
            else
            {
                if (answer.Length > 80) return null;

                encodePasswordQuestionAnswer = EncodePassword(answer.ToLower(), salt);
            }

            var users = GetByUsernameAndQuestionAnswer(username, encodePasswordQuestionAnswer);

            foreach (var user in users)
            {
                user.ResetPassword(encodeNewPassword);
                Save(user);
                break;
            }

            return newPassword;
        }

        /// <summary>
        /// The unlock user.
        /// </summary>
        /// <param name="userName">
        /// The user name.
        /// </param>
        /// <returns>
        /// The unlock user.
        /// </returns>
        public override bool UnlockUser(string userName)
        {
            if (!userName.Validate(true, true, true, 100)) return false;
            
            var user = GetByUsername(userName);

            if (user != null)
            {
                user.UnlockUser();
                Save(user);
                return true;
            }

            return false;
        }

        /// <summary>
        /// The update user.
        /// </summary>
        /// <param name="user">
        /// The user.
        /// </param>
        public override void UpdateUser(MembershipUser user)
        {
            var userId = (TId)user.ProviderUserKey;
            var cmsUser = GetById(userId);

            cmsUser.UpdateUser(user.UserName, user.Email, user.Comment, user.IsApproved, user.IsLockedOut,
                               user.LastActivityDate, user.LastLockoutDate, user.LastLoginDate,
                               user.LastPasswordChangedDate, user.PasswordQuestion);
            Save(cmsUser);
        }

        /// <summary>
        /// The validate user.
        /// </summary>
        /// <param name="username">
        /// The username.
        /// </param>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <returns>
        /// The validate user.
        /// </returns>
        public override bool ValidateUser(string username, string password)
        {
            if (!username.Validate(true, true, true, 100)) return false;
            
            var salt = GetSalt(username);

            if (salt == null) return false;
            
            var encodePassword = EncodePassword(password, salt);

            var user = GetByUsername(username);

            var check = true;
            if (user != null)
            {
                if (!user.IsApproved) return false;
                
                if (user.IsLockedOut)
                {
                    var now = DateTime.UtcNow;
                    var window = now.Subtract(user.LastLockoutDate);
                    if (window.TotalMinutes >= PasswordAttemptWindow)
                    {
                        user.UnlockUser();
                    }
                    else
                    {
                        check = false;
                    }
                }

                if (user.Password != encodePassword)
                {
                    user.LoginTry(MaxInvalidPasswordAttempts);
                    check = false;
                }
            }

            Save(user);
            return check;
        }

        public IUserFactory<TModel, TId> UserFactory
        {
            get;
            set;
        }
    }
}