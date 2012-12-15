using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Security;

namespace Authentication
{
    public abstract class BaseRoleMembershipProvider<TModel, TId> : RoleProvider where TModel : IRole<TId>
    {
        public abstract IEnumerable<TModel> GetRoles();

        public override bool IsUserInRole(string username, string roleName)
        {
            var results = from p in GetRoles()
                          where p.Name == roleName
                          from u in p.Users
                          where u.Username == username
                          select u;

            return results.Any();
        }   

        public override string[] GetRolesForUser(string username)
        {
            var results = from p in GetRoles()
                          from u in p.Users
                          where u.Username == username
                          select p;

            return results.Select(p => p.Name).ToArray();
        }

        public override void CreateRole(string roleName)
        {
            RoleFactory.CreateRole(roleName);
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            var results = from p in GetRoles()
                          where p.Name == roleName
                          select p;

            if (throwOnPopulatedRole)
            {
                var populated = results.Select(p => p.Users.Any());

                if (populated.Any())
                {
                    throw new Exception("Role is populated");
                }
            }

            return RoleFactory.DeleteRole(roleName);
        }

        public override bool RoleExists(string roleName)
        {
            var results = from p in GetRoles()
                          where p.Name == roleName
                          select p;

            return results.Any();
        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            var results = from p in GetRoles()
                          from role in roleNames
                          where p.Name == role
                          select p.Name;

            foreach (var result in results)
            {
                foreach (var username in usernames)
                {
                    RoleFactory.AddUserToRole(username, result);
                }
            }
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            var results = from p in GetRoles()
                          from role in roleNames
                          where p.Name == role
                          select p.Name;

            foreach (var result in results)
            {
                foreach (var username in usernames)
                {
                    RoleFactory.RemoveUsersFromRoles(username, result);
                }
            }
        }

        public override string[] GetUsersInRole(string roleName)
        {
            var results = from p in GetRoles()
                          where p.Name == roleName
                          select p.Users;

            return results.Any() ? results.First().Select(p => p.Username).ToArray() : new string[0];
        }

        public override string[] GetAllRoles()
        {
            return GetRoles().Select(p => p.Name).ToArray();
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            var results = from p in GetRoles()
                          where p.Name == roleName
                          from u in p.Users
                          where u.Username == usernameToMatch
                          select u;

            return results.Any() ? results.Select(p => p.Username).ToArray() : new string[0];
        }

        public abstract override string ApplicationName
        {
            get;
            set;
        }

        public IRoleFactory<TModel, TId> RoleFactory
        {
            get;
            set;
        }

    }
}