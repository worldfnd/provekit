# Contributing

Thank you for your interest in contributing! We value your contributions. 🙏

This guide will discuss how the team handles [Commits](#commits), [Pull Requests](#pull-requests), [Releases](#releases), the [Changelog](#changelog), and [Response time](#response-time).

**Note:** We won't force external contributors to follow this verbatim, but following these guidelines definitely helps us in accepting your contributions.

## Commits

We want to keep our commits small and focused. This allows for easily reviewing individual commits and/or splitting up pull requests when they grow too big. Additionally, this allows us to merge smaller changes quicker.

When committing, it's often useful to use the `git add -p` workflow to decide on what parts of the changeset to stage for commit.

## Pull Requests

Before you create a pull request, search for any issues related to the change you are making. If none exist already, create an issue that thoroughly describes the problem that you are trying to solve. These are used to inform reviewers of the original intent and should be referenced via the pull request template.

Pull Requests should be focused on the specific change they are working towards. If prerequisite work is required to complete the original pull request, that work should be submitted as a separate pull request.

This strategy avoids scenarios where pull requests grow too large/out-of-scope and don't get proper reviews—we want to avoid "LGTM, I trust you" reviews.

### Conventional Commits

We use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) naming conventions for PRs, which help with releases and changelogs. Please use the following format for PR titles:

```
<type>[optional scope]: <description>
```

Generally, we want to only use the three primary types defined by the specification:

- `feat:` - This should be the most used type, as most work we are doing in the project are new features. Commits using this type will always show up in the Changelog.
- `fix:` - When fixing a bug, we should use this type. Commits using this type will always show up in the Changelog.
- `chore:` - The least used type, these are not included in the Changelog unless they are breaking changes. But remain useful for an understandable commit history.

#### Breaking Changes

Annotating BREAKING CHANGES is extremely important to our release process and versioning. To mark a commit as breaking, we add the ! character after the type, but before the colon. For example:

```
feat!: Rename nargo build to nargo check (#693)
```

```
feat(nargo)!: Enforce minimum rustc version
```

#### Scopes

Scopes significantly improve the Changelog, so we want to use a scope whenever possible. If we are only changing one part of the project, we can use the name of the crate, like (nargo) or (noirc_driver). If a change touches multiple parts of the codebase, there might be a better scope, such as using (syntax) for new language features.

```
feat(nargo): Add support for wasm backend (#234)
```

```
feat(syntax): Implement String data type (#123)
```

### Typos and other small changes

Significant changes, like new features or important bug fixes, typically have a more pronounced impact on the project’s overall development. For smaller fixes, such as typos, we encourage you to report them as Issues instead of opening PRs. This approach helps us manage our resources effectively and ensures that every change contributes meaningfully to the project. PRs involving such smaller fixes will likely be closed and incorporated in PRs authored by the core team.

### Reviews

For any repository in the organization, we require code review & approval by **one** team member before the changes are merged, as enforced by GitHub branch protection. Non-breaking pull requests may be merged at any time. Breaking pull requests should only be merged when the team has general agreement of the changes and is preparing a breaking release.

### Documentation

Breaking changes must be documented, either through adding/updating existing docs or README.md.

## Releases

Releases are managed by [Release Please](https://github.com/googleapis/release-please) which runs in a GitHub Action whenever a commit is made on the master branch.

Release Please parses Conventional Commit messages and opens (or updates) a pull request against the master branch that contains updates to the versions & Changelog within the project. If it doesn't detect any breaking change commits, it will only increment the "patch" version; however, if it detects a breaking change commit, it will increment the "minor" version number to indicate a breaking release.

When we are ready to release the version, we approve and squash merge the release pull request into master. Release Please will detect this merge and generate the appropriate tags for the release. Additional release steps may be triggered inside the GitHub Action to automate other parts of the release process.

There is no strict release cadence, but a new release is usually cut every 1 to 2 months.

## Changelog

The Changelog is automatically managed by Release Please and informed by the Conventional Commits (as discussed above).

## Response time

The team will respond to issues and PRs within 1 week from submission.
