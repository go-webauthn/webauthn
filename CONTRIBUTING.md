# Contributing Guidelines

## Dependencies

Additional dependencies should be avoided where practical. Each additional dependency adds to the maintenance burden
of the library, and increases the risk of introducing security vulnerabilities via direct methods or through indirect
methods such as supply chain attacks.

Dependencies should typically be used when the complexity of maintaining a particular function is too high to be
reasonably maintained by a single developer. A great example of this are cryptographic functions or encoding functions
such as CBOR.

## Style

### Unit Tests

All new code should be accompanied by unit tests. The following are normal conventions for unit testing:

1. Where practical unit tests should be comprised of a main test function and a list of test cases:
   1. The test cases should be held in a `[]struct{}` named `testCases` and each test case should be a `struct{}` with
      the `name` field which is the name to be used as the subtest name.
   2. Each subtest should have a field or fields with the `have` naming convention.
   3. Each subtest should have a field or fields with the `expected` naming convention.
2. Errors should be verified using `assert.EqualError` / `require.EqualError`, or `assert.NoError` / `require.NoError`:
   1. Exact error checking ensures that the output to the consumers of this library is transparent to the developers of
      the library to ensure we're communicating useful information.
   2. Additional checks of the error can occur to check the fields not produced as part of the `.Error()` output.
3. All constants, variables, or functions exclusively used in tests should be in a `_test.go` file.
4. All test files should have the following in-order layout:
   1. `package <package>`
   2. `import (`
   3. All `func Test*` functions
   4. Everything else
5. All tests should be successful with the `go test -race ./...` command.

### Documentation

All publicly exported members should be documented using the GoDoc format. Members include:

- Functions
- Struct Types
- Struct Type Fields
- Struct Type Functions
- Interface Types
- Interface Type Functions

Some specific notes for documentation:

1. If you're referring to another area of the code base such as a struct you should surround that reference with `[` and
   `]` to ensure it's linked in the documentation.
2. The comment for any member should start with its exact name, or be the second word in the comment.
3. Comments should be limited to 120 characters per-line.
 
## Pull Request Conventions

It's encouraged to discuss proposed changes prior to opening a PR, especially when the change is large.

Pull request subjects should have the same format as the [Commit Message Header](#commit-message-header). 

### Documentation / Specifications 

You should include reference documentation specifically if there is a section in the W3C Webauthn specification that
relates to your pull request and explain in the PR how it implements the spec or implements the spec more closely.

### Force Push

Force pushing once a pull request has been opened is heavily frowned upon. All pull requests will be merged using 
`git merge --squash` to avoid cluttering the master branch history with changes made during the review process. As such
the only purpose force pushing to a branch once a pull request is opened is making it harder for reviewers to review
your code; especially if a review has already taken place or has been started.

## Commit Message Convention

_This specification is inspired by and supersedes the [AngularJS commit message format][commit-message-format]. This
is an adapted version of the [Angular commit guidelines]._

We have very precise rules over how our Git commit messages must be formatted. 
This format leads to **easier to read commit history**.

Each commit message consists of a **header**, a **body**, and a **footer**.

```
<header>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

The `header` is mandatory and must conform to the [Commit Message Header](#commit-message-header) format.

The `body` is mandatory for all commits except for those of type "docs". When the body is present it must be at least 20
characters long and must conform to the [Commit Message Body](#commit-message-body) format.

The `footer` is optional. The [Commit Message Footer](#commit-message-footer) format describes what the footer is used
for and the structure it must have.

#### Commit Message Header

```
<type>(<scope>): <short summary>
  │       │             │
  │       │             └─⫸ Summary in present tense. Not capitalized. No period at the end.
  │       │
  │       └─⫸ Commit Scope: metadata|protocol|webauthn
  │
  └─⫸ Commit Type: build|ci|docs|feat|fix|perf|refactor|test
```

The `<type>` and `<summary>` fields are mandatory, the `(<scope>)` field is optional.


##### Type

Must be one of the following:

* **build**: Changes that affect the build system or external dependencies (example scopes: gulp, broccoli, npm)
* **ci**: Changes to our CI configuration files and scripts (examples: CircleCi, SauceLabs)
* **docs**: Documentation only changes
* **feat**: A new feature
* **fix**: A bug fix
* **perf**: A code change that improves performance
* **refactor**: A code change that neither fixes a bug nor adds a feature
* **revert**: Revert a commit
* **release**: Publish a release
* **test**: Adding missing tests or correcting existing tests

##### Scope

The scope should be the name of the npm package affected (as perceived by the person reading the changelog generated
from commit messages).

The following is the list of supported scopes:

* `metadata`
* `protocol`
* `webauthn`

##### Summary

Use the summary field to provide a succinct description of the change:

* use the imperative, present tense: "change" not "changed" nor "changes"
* don't capitalize the first letter
* no dot (.) at the end

#### Commit Message Body

Just as in the summary, use the imperative, present tense: "fix" not "fixed" nor "fixes".

Explain the motivation for the change in the commit message body. This commit message should explain _why_ you are
making the change. You can include a comparison of the previous behavior with the new behavior in order to illustrate
the impact of the change.

#### Commit Message Footer

The footer can contain information about breaking changes and deprecations and is also the place to reference GitHub 
issues and other PRs that this commit closes or is related to.

For example:

```
BREAKING CHANGE: <breaking change summary>
<BLANK LINE>
<breaking change description + migration instructions>
<BLANK LINE>
<BLANK LINE>
Fixes #<issue number>
```

or

```
DEPRECATED: <what is deprecated>
<BLANK LINE>
<deprecation description + recommended update path>
<BLANK LINE>
<BLANK LINE>
Closes #<pr number>
```

Breaking Change section should start with the phrase "BREAKING CHANGE: " followed by a summary of the breaking change, 
a blank line, and a detailed description of the breaking change that also includes migration instructions.

Similarly, a Deprecation section should start with "DEPRECATED: " followed by a short description of what is deprecated,
a blank line, and a detailed description of the deprecation that also mentions the recommended update path.

### Revert commits

If the commit reverts a previous commit, it should begin with `revert: `, followed by the header of the reverted commit.

The content of the commit message body should contain:

- information about the SHA of the commit being reverted in the following format: `This reverts commit <SHA>`,
- a clear description of the reason for reverting the commit message.

[commit-message-format]: https://docs.google.com/document/d/1QrDFcIiPjSLDn3EL15IJygNPiHORgU1_OOAqWjiDU5Y/edit#
[Angular commit guidelines]: https://github.com/angular/angular/blob/master/CONTRIBUTING.md#commit