﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public interface IRoleFactory<TModel, TId> where TModel : IRole<TId>
    {
        TModel CreateRole(string roleName);

        bool DeleteRole(string roleName);

        bool RoleExists(string roleName);

        void AddUserToRole(string userName, string roleName);

        void RemoveUsersFromRoles(string usernames, string roleNames);
    }
}