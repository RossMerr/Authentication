using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public interface IUserFactory<TModel, TId> where TModel : IUser<TId>
    {
        TModel CreateUser(string username, string password, string email, string passwordQuestion,
                          string questionAnswer, bool isApproved, string salt);

    }
}
