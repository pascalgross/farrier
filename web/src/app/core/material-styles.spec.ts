import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';

/**
 * A host for the Material components whose appearance depends on a global stylesheet.
 *
 * The spec below reads a computed style rather than a class list, because the class was present all
 * along and no rule matched it. Asserting on the markup would have passed while the application
 * rendered the word "notifications" across its own toolbar.
 */
@Component({
  selector: 'farrier-material-styles-probe',
  imports: [MatIconModule],
  template: `<mat-icon>notifications</mat-icon>`,
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
});
