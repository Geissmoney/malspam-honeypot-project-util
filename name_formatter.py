import random
name = """Dale Dawes 
Kevin Allison 
Charlene Randall 
Sylvia Smith 
Glenys Brown 
"""

# Parse the names into a list of (first, last) tuples
names = [tuple(full_name.strip().split()) for full_name in name.split('\n')]
random.shuffle(names)  # Randomize the order

# Calculate names per domain (ensure even distribution)
names_per_domain = len(names) // 4

# Email format functions


def format_domain_one(first, last):
    return f"{first[0].lower()}{last.lower()}@target-domain.one"


def format_domain_two(first, last):
    return f"{first[0].lower()}{last.lower()}@target-domain.two"


def format_domain_three(first, last):
    return f"{first.lower()}.{last.lower()}@target-domain.three"


def format_domain_four(first, last):
    return f"{first.lower()}.{last.lower()}@target-domain.four"


# Distribute names across domains
domains = {
    'one.txt': (names[:names_per_domain], format_domain_one),
    'two.txt': (names[names_per_domain:names_per_domain*2], format_domain_two),
    'three.txt': (names[names_per_domain*2:names_per_domain*3], format_domain_three),
    'four.txt': (names[names_per_domain*3:], format_domain_four),
}

# Generate and save email lists
for filename, (name_list, formatter) in domains.items():
    with open(filename, 'w') as f:
        emails = [formatter(first, last) for first, last in name_list]
f.write('\n'.join(emails))
print(f"Generated {len(emails)} emails in {filename}")
