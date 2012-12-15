using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public interface IRole<TId>
    {
        TId Id { get; }
        string Name { get; }
        IEnumerable<IUser> Users { get; }
    }
}
