# Password Visibility Toggle Spec

## ADDED Requirements

### Requirement: Password input SHALL have a show/hide toggle

Each password input on the login and signup pages MUST include an inline toggle button that allows the user to switch between masked and visible password display.

#### Scenario: Toggle is visible in the password input

- **WHEN** the login page or signup page renders
- **THEN** each password input contains an eye icon button positioned at the right edge inside the input field

#### Scenario: Clicking toggle reveals password

- **WHEN** the user clicks the eye icon button while the password is masked
- **THEN** the input type changes to `text` and the icon changes to an eye-off symbol

#### Scenario: Clicking toggle hides password

- **WHEN** the user clicks the eye-off icon button while the password is visible
- **THEN** the input type changes to `password` and the icon changes to an eye symbol

#### Scenario: Toggle does not submit the form

- **WHEN** the user clicks the toggle button
- **THEN** the form is NOT submitted

#### Scenario: Toggle is accessible

- **WHEN** a screen reader reads the toggle button
- **THEN** it announces "Show password" when hiding or "Hide password" when showing, and reports its pressed state via `aria-pressed`

#### Scenario: Password text does not overlap toggle

- **WHEN** the user types a long password with the toggle visible
- **THEN** the rightmost characters of the password are not obscured by the toggle button (input has sufficient right padding)

### Requirement: Toggle uses inline SVG icons

The show/hide toggle MUST use inline SVG icons with no external dependencies.

#### Scenario: Eye icon is displayed when password is hidden

- **WHEN** the password is in masked mode
- **THEN** an eye-shaped SVG icon is displayed inside the button

#### Scenario: Eye-off icon is displayed when password is visible

- **WHEN** the password is in visible mode
- **THEN** an eye-off-shaped SVG icon is displayed inside the button