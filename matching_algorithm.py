"""
matching_algorithm.py
---------------------

This module implements a simple rule‑based matching algorithm for connecting
musicians based on survey responses.  It defines a ``UserProfile`` data class,
computes a compatibility score between two users, and provides a function to
retrieve each user’s top matches.  A small test suite is included at the
bottom of the file to verify that the scoring logic behaves as expected.

The scoring algorithm considers the following signals:

* **Location proximity**: one point if the users live in the same city.
* **Goal alignment**: two points if both users share the same goal (e.g.,
  ``casual_jams``), or one point if both are looking for something in the
  “casual/learn” category.
* **Commitment alignment**: up to two points depending on how closely their
  commitment levels (``casual``, ``focused``, ``dedicated``) align.
* **Collaboration style overlap**: one point per shared style (in‑person,
  remote, hybrid) up to a maximum of two points.
* **Energy alignment**: one point per shared collaboration energy (e.g.,
  experimental, structured, performance‑driven) up to a maximum of two points.
* **Instrument complementarity**: one point if their primary instruments are
  different.
* **Genre overlap**: one point per shared genre up to two points.

If any user lists a keyword in their ``dealbreakers`` that appears in the
other user’s motivation, the compatibility score for that pair is zero.  This
simple logic can be extended as needed.

Example usage::

    from matching_algorithm import UserProfile, find_best_matches

    users = [
        UserProfile(
            id=1,
            city="New York",
            postal_code="10001",
            primary_instruments={"guitar"},
            secondary_instruments={"bass"},
            genres={"rock", "pop"},
            goal="casual_jams",
            commitment="casual",
            styles={"in_person", "remote"},
            energies={"experimental"},
            motivation="I want to jam casually and learn new skills."
        ),
        # ... other users ...
    ]
    matches = find_best_matches(users)
    print(matches[1])  # prints top matches for user 1

The module also contains a simple ``run_tests`` function that runs a few
assertions; it is executed when you run the file directly.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


@dataclass
class UserProfile:
    """Represents a musician’s profile collected from the survey."""

    id: int
    city: str
    postal_code: str
    primary_instruments: Set[str]
    secondary_instruments: Set[str]
    genres: Set[str]
    goal: str
    commitment: str
    styles: Set[str]
    energies: Set[str]
    motivation: str
    dealbreakers: Set[str] = field(default_factory=set)


def compute_score(a: UserProfile, b: UserProfile) -> int:
    """Compute a compatibility score between two users.

    The function returns an integer score; a higher score indicates greater
    compatibility.  If one user’s dealbreaker appears in the other user’s
    motivation text, the function returns 0 immediately.
    """

    # Dealbreaker check
    for d in a.dealbreakers:
        if d.lower() in b.motivation.lower():
            return 0
    for d in b.dealbreakers:
        if d.lower() in a.motivation.lower():
            return 0

    score = 0

    # 1. Location proximity
    if a.city.lower() == b.city.lower():
        score += 1

    # 2. Goal alignment
    if a.goal == b.goal:
        score += 2
    else:
        casuals = {"casual_jams", "learn"}
        if a.goal in casuals and b.goal in casuals:
            score += 1

    # 3. Commitment alignment
    commitments_order = ["casual", "focused", "dedicated"]
    try:
        diff = abs(commitments_order.index(a.commitment) - commitments_order.index(b.commitment))
        if diff == 0:
            score += 2
        elif diff == 1:
            score += 1
    except ValueError:
        pass  # Unknown commitment names are ignored

    # 4. Collaboration style overlap (max 2)
    shared_styles = a.styles & b.styles
    score += min(len(shared_styles), 2)

    # 5. Energy alignment (max 2)
    shared_energies = a.energies & b.energies
    score += min(len(shared_energies), 2)

    # 6. Instrument complementarity (1 if primary instruments differ)
    if not a.primary_instruments & b.primary_instruments:
        score += 1

    # 7. Genre overlap (max 2)
    shared_genres = a.genres & b.genres
    score += min(len(shared_genres), 2)

    return score


def find_best_matches(users: List[UserProfile], top_n: int = 2) -> Dict[int, List[Tuple[int, int]]]:
    """Return each user's top matches.

    For each user in the input list, compute scores against all other users and
    return up to ``top_n`` matches sorted in descending order of score.  The
    returned dictionary maps each user’s ``id`` to a list of tuples
    ``(other_user_id, score)``.
    """

    matches: Dict[int, List[Tuple[int, int]]] = {}

    for user in users:
        scored: List[Tuple[int, int]] = []
        for other in users:
            if user.id == other.id:
                continue
            s = compute_score(user, other)
            if s > 0:
                scored.append((other.id, s))
        # Sort by score descending then by ID for deterministic ordering
        scored.sort(key=lambda x: (-x[1], x[0]))
        matches[user.id] = scored[:top_n]

    return matches


def run_tests():  # pragma: no cover
    """Run a few simple assertions to validate the algorithm.

    To keep things simple, this test function prints an affirmative message
    when all assertions pass.  Run this file directly (``python
    matching_algorithm.py``) to execute the tests.
    """

    # Define three sample users
    user1 = UserProfile(
        id=1,
        city="New York",
        postal_code="10001",
        primary_instruments={"guitar"},
        secondary_instruments={"bass"},
        genres={"rock", "pop"},
        goal="casual_jams",
        commitment="casual",
        styles={"in_person", "remote"},
        energies={"experimental"},
        motivation="I want to jam casually and learn new skills.",
        dealbreakers={"no late-night"}
    )

    user2 = UserProfile(
        id=2,
        city="New York",
        postal_code="10002",
        primary_instruments={"drums"},
        secondary_instruments={"guitar"},
        genres={"rock", "jazz"},
        goal="casual_jams",
        commitment="casual",
        styles={"in_person"},
        energies={"experimental", "structured"},
        motivation="Looking for experimental jams and some live shows.",
        dealbreakers=set()
    )

    user3 = UserProfile(
        id=3,
        city="Chicago",
        postal_code="60601",
        primary_instruments={"guitar"},
        secondary_instruments={"vocals"},
        genres={"hip hop"},
        goal="long_term_project",
        commitment="dedicated",
        styles={"remote"},
        energies={"structured"},
        motivation="Want to form a serious long-term project.",
        dealbreakers={"no covers"}
    )

    # Expect user1 and user2 to be more compatible than user1 and user3
    assert compute_score(user1, user2) > compute_score(user1, user3)
    assert compute_score(user1, user2) > 0
    assert compute_score(user1, user3) >= 0

    # Best matches mapping
    matches = find_best_matches([user1, user2, user3], top_n=2)
    # user1's top match should be user2
    assert matches[1][0][0] == 2
    # user2's top match should be user1
    assert matches[2][0][0] == 1
    # user3 may have no match or low score (depending on values)
    assert 3 in matches

    print("All tests passed!")


if __name__ == "__main__":  # pragma: no cover
    run_tests()

