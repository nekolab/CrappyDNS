/*
 * Copyright (C) 2018  Sunny <ratsunny@gmail.com>
 *
 * This file is part of CrappyDNS.
 *
 * CrappyDNS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CrappyDNS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "runas.h"

#include <errno.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>

#include "utils.h"

int RunAs(const char* user) {
  if (!user)
    return 0;

  char* endptr;
  long uid = strtol(user, &endptr, 10);
  if (endptr == user || (uid == 0 && *user != '0')) {
    uid = -1;
  }

#ifdef HAVE_GETPWNAM_R
  struct passwd pwdbuf, *pwd;
  ::memset(&pwdbuf, 0, sizeof(struct passwd));
  size_t buflen;
  int err;

  for (buflen = 128;; buflen *= 2) {
    char buf[buflen]; /* variable length array */

    /* Note that we use getpwnam_r() instead of getpwnam(),
     * which returns its result in a statically allocated buffer and
     * cannot be considered thread safe. */
    err = uid >= 0 ? getpwuid_r((uid_t)uid, &pwdbuf, buf, buflen, &pwd)
                   : getpwnam_r(user, &pwdbuf, buf, buflen, &pwd);

    if (err == 0 && pwd) {
      /* setgid first, because we may not be allowed to do it anymore after
       * setuid */
      if (setgid(pwd->pw_gid) != 0) {
        ERR << "Could not change group id to that of run_as user '"
            << pwd->pw_name << "': " << strerror(errno) << ENDL;
        return 0;
      }

      if (initgroups(pwd->pw_name, pwd->pw_gid) == -1) {
        ERR << "Could not change supplementary groups for user '"
            << pwd->pw_name << "'." << ENDL;
        return 0;
      }

      if (setuid(pwd->pw_uid) != 0) {
        ERR << "Could not change user id to that of run_as user '"
            << pwd->pw_name << "': " << strerror(errno) << ENDL;
        return 0;
      }
      break;
    } else if (err != ERANGE) {
      if (err) {
        ERR << "Run as user '" << user
            << "' could not be found: " << strerror(err) << ENDL;
      } else {
        ERR << "Run as user '" << user << "' could not be found." << ENDL;
      }
      return 0;
    } else if (buflen >= 16 * 1024) {
      /* If getpwnam_r() seems defective, call it quits rather than
       * keep on allocating ever larger buffers until we crash. */
      ERR << "getpwnam_r() requires more than " << (unsigned)buflen
          << " bytes of buffer space." << ENDL;
      return 0;
    }
    /* Else try again with larger buffer. */
  }
#else
  /* No getpwnam_r() :-(  We'll use getpwnam() and hope for the best. */
  struct passwd* pwd;

  if (!(pwd = uid >= 0 ? getpwuid((uid_t)uid) : getpwnam(user))) {
    ERR << "Run as user '" << user << "' could not be found." << ENDL;
    return 0;
  }
  /* setgid first, because we may not allowed to do it anymore after setuid */
  if (setgid(pwd->pw_gid) != 0) {
    ERR << "Could not change group id to that of run_as user '" << pwd->pw_name
        << "': " << strerror(errno) << ENDL;
    return 0;
  }
  if (initgroups(pwd->pw_name, pwd->pw_gid) == -1) {
    ERR << "Could not change supplementary groups for user '" << pwd->pw_name
        << "'." << ENDL;
    return 0;
  }
  if (setuid(pwd->pw_uid) != 0) {
    ERR << "Could not change user id to that of run_as user '" << pwd->pw_name
        << "': " << strerror(errno) << ENDL;
    return 0;
  }
#endif

  return 1;
}

bool IsRoot() {
  return geteuid() == 0;
}
