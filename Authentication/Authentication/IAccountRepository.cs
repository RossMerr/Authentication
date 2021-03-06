﻿using System;
using System.Collections.Generic;
using MvcContrib.Pagination;

namespace Authentication
{
    public interface IAccountRepository<TUser, TUserList, TId> where TUser : IUser<TId>
    {
        IPagination<TUserList> GetPagedList(int pageIndex, int pageSize);

        TUser GetByUsername(string username);

        bool HasUserByEmail(string email);

        int GetNumberOfUsersOnline(DateTime period);

        IEnumerable<TUser> GetByEmailAddress(string email, int pageIndex, int pageSize);
        IEnumerable<TUser> GetByUsername(string username, int pageIndex, int pageSize);
        IEnumerable<TUser> GetByUsernameAndQuestionAnswer(string username, string encodePasswordQuestionAnswer);
        void Save(TUser obj);
        void Delete(TUser obj);
        IEnumerable<TUser> FindAll();
        TUser FindOne(TId id);
    }
}
