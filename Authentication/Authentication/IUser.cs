using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public interface IUser
    {
        string Username { get; }
        string Password { get; }
        string Salt { get; }
        string PasswordQuestion { get; }

        string QuestionAnswer { get; }
        string Email { get; }
        string Comment { get; }
        bool IsApproved { get; }
        bool IsLockedOut { get; }
        DateTime LastActiveDate { get; }
        DateTime LastLockoutDate { get; }
        DateTime LastLoginDate { get; }
        DateTime LastPasswordChangedDate { get; }
        DateTime DateCreated { get; }
        int LoginTrys { get; }

        void ChangePassword(string password, string salt);
        void ChangePasswordQuestionAndAnswer(string passwordQuestion, string passwordAnswer);
        void ResetPassword(string password);
        void UnlockUser();
        void LoginTry(int maxInvalidPasswordAttempts);
        void LoggedIn();
        void UserIsOnline();

        void UpdateUser(string username, string email, string comment, bool isApproved, bool isLockedOut,
                        DateTime lastActivityDate, DateTime lastLockoutDate, DateTime lastLoginDate,
                        DateTime lastPasswordChangedDate, string passwordQuestion);
    }

    public interface IUser<TId> : IUser
    {
        TId Id { get; }
    }

    public abstract class User<TId> : IUser<TId>
    {
        #region IUser<TId> Members

        public abstract string Username { get; protected set; }

        public abstract string Password { get; protected set; }

        public abstract string Salt { get; protected set; }

        public abstract string PasswordQuestion { get; protected set; }

        public abstract string QuestionAnswer { get; protected set; }

        public abstract string Email { get; protected set; }

        public abstract string Comment { get; protected set; }

        public abstract bool IsApproved { get; protected set; }

        public abstract bool IsLockedOut { get; protected set; }

        public abstract DateTime LastActiveDate { get; protected set; }

        public abstract DateTime LastLockoutDate { get; protected set; }

        public abstract DateTime LastLoginDate { get; protected set; }

        public abstract DateTime LastPasswordChangedDate { get; protected set; }

        public abstract DateTime DateCreated { get; protected set; }

        public abstract int LoginTrys { get; protected set; }

        public virtual void ChangePassword(string password, string salt)
        {
            Password = password;
            Salt = salt;
        }

        public virtual void ChangePasswordQuestionAndAnswer(string passwordQuestion, string questionAnswer)
        {
            PasswordQuestion = passwordQuestion;
            QuestionAnswer = questionAnswer;
        }

        public virtual void ResetPassword(string password)
        {
            Password = password;
        }

        public virtual void UnlockUser()
        {
            IsLockedOut = false;
            LoginTrys = 0;
        }

        public virtual void LoginTry(int maxInvalidPasswordAttempts)
        {
            LoginTrys++;
            if (LoginTrys >= maxInvalidPasswordAttempts)
            {
                IsLockedOut = true;
                LastLockoutDate = DateTime.UtcNow;
            }
        }

        public virtual void LoggedIn()
        {
            LastLoginDate = DateTime.UtcNow;
            LastActiveDate = LastLoginDate;
            LoginTrys = 0;
        }

        public virtual void UserIsOnline()
        {
            LastActiveDate = DateTime.UtcNow;
        }

        public virtual void UpdateUser(string username, string email, string comment, bool isApproved, bool isLockedOut,
                                       DateTime lastActivityDate, DateTime lastLockoutDate, DateTime lastLoginDate,
                                       DateTime lastPasswordChangedDate, string passwordQuestion)
        {
            Email = email;
            Comment = comment;
            IsApproved = isApproved;
            IsLockedOut = isLockedOut;
            LastActiveDate = lastActivityDate;
            LastLockoutDate = lastLockoutDate;
            LastLoginDate = lastLoginDate;
            LastPasswordChangedDate = lastPasswordChangedDate;
            PasswordQuestion = passwordQuestion;
            Username = username;
        }

        public virtual TId Id { get; protected set; }

        #endregion
    }
}