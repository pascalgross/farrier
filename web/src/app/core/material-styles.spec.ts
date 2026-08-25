import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';

/**
 * A host for the Material components whose appearance depends on a global stylesheet.
 *
 * Both specs below read a computed style rather than a class list, because in both cases the markup
 * was correct all along and no rule matched it. An assertion about the DOM would have passed while
 * the application rendered the word "notifications" across its own toolbar.
 */
@Component({
  selector: 'farrier-material-styles-probe',
  imports: [MatFormFieldModule, MatIconModule, MatInputModule],
  template: `
    <mat-icon>notifications</mat-icon>
    <mat-form-field appearance="outline">
      <mat-label>Bearer token</mat-label>
      <input matInput />
    </mat-form-field>
  `,
})
class Probe {}

/** Renders the probe and returns its root element, attached to the document so styles resolve. */
function render(): HTMLElement {
  TestBed.configureTestingModule({
    imports: [Probe],
    providers: [provideZonelessChangeDetection()],
  });
  const fixture = TestBed.createComponent(Probe);
  fixture.detectChanges();
  return fixture.nativeElement as HTMLElement;
}

describe('the global stylesheet, where it meets Angular Material', () => {
  it('gives mat-icon the bundled icon font, so a ligature name renders as a glyph', () => {
    const icon = render().querySelector('mat-icon');
    expect(icon).not.toBeNull();

    // @fontsource ships the @font-face and not the class that uses it. Without src/styles.scss
    // supplying that half, this is whatever body is set in — and every icon in the application is
    // its own name in words.
    const style = getComputedStyle(icon as Element);
    expect(style.fontFamily).toContain('Material Icons');
    expect(style.fontFeatureSettings).toContain('liga');
  });

  it('draws no border down the middle of an outlined field', () => {
    const notch = render().querySelector('.mdc-notched-outline__notch');
    expect(notch).not.toBeNull();

    // Material leaves this side at the browser default of `border-style: none` and sets a width on
    // all four sides, which is harmless until Tailwind's Preflight sets `border: 0 solid` globally
    // and gives the width something to draw: a full-height rule through the middle of the field.
    const style = getComputedStyle(notch as Element);
    expect(style.borderInlineEndStyle).toBe('none');
    expect(style.borderInlineEndWidth).toBe('0px');
  });
});
