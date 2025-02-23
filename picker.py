"""
Copyright (C) 2025 Arseniy Astankov

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import sys
import random

if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <n>")
    sys.exit(1)

try:
    n = int(sys.argv[1])
except ValueError:
    print("Error: n must be an integer")
    sys.exit(1)

lines = set()
for line in sys.stdin:
    lines.add(line.strip())

random_lines = random.sample(list(lines), min(n, len(lines)))

for line in random_lines:
    print(line)
