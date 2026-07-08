/***************************************************************************
 *   Copyright (C) 2008-2021 by Andrzej Rybczak                            *
 *   andrzej@rybczak.net                                                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.              *
 ***************************************************************************/

#ifndef NCMPCPP_SCROBBLER_H
#define NCMPCPP_SCROBBLER_H

#include "song.h"

namespace Scrobbler {

// Load or obtain a Last.fm session key.  Call once after MPD connects and
// Config is populated.  No-op if lastfm_scrobble is disabled.
void initialize();

// Called on every song change.  Submits a scrobble for |prev| if its play
// threshold was met, then sends an updateNowPlaying notification for |next|.
// |prev_start_time| is the unix timestamp when |prev| started playing.
// Pass an empty MPD::Song{} for |prev| on the very first song.
void songChanged(const MPD::Song &prev,
                 unsigned prev_start_time,
                 bool     prev_threshold_met,
                 const MPD::Song &next);

// Called when MPD transitions to a stopped state so we can attempt to
// scrobble the last song if the threshold was already met.
void playerStopped(const MPD::Song &last,
                   unsigned last_start_time,
                   bool     last_threshold_met);

}

#endif // NCMPCPP_SCROBBLER_H
